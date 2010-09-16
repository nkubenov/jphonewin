using System;
using System.Drawing;
using System.Windows.Forms;
using System.Collections.Generic;
using System.IO;
using Microsoft.Win32;
using LibUsbDotNet;
using LibUsbDotNet.Main;
using LibUsbDotNet.DeviceNotify;
using Dokan;

static class Global
{
	public delegate void LogEventHandler(string sMessage, bool bIsContinuation);
	public static event LogEventHandler LogUpdated;
	private static System.Threading.Mutex LogMutex = new System.Threading.Mutex(false);

	// Some lines ("success!" confirmation, etc.) should be treated differently
	// when they aren't full log entries by themselves.
	public static void Log(string sMessage, bool bIsContinuation)
	{
		LogMutex.WaitOne();
		if (LogUpdated != null) LogUpdated(sMessage, bIsContinuation);
		LogMutex.ReleaseMutex();
	}

	public static void Log(string sMessage)
	{
		Log(sMessage, false);
	}
}

class iPhoneDiskApplication : Form
{
	private class ComboBoxItem
	{
		Object oItem;
		string sName;

		public ComboBoxItem(Object I, string Name)
		{
			oItem = I;
			sName = Name;
		}

		public override string ToString()
		{
			return sName;
		}

		public Object Item { get { return oItem; } }
	}

	Icon iApplication;
	NotifyIcon niTrayIcon;

	ComboBox cbDeviceList;
	Label lbText;
	Button buMount;
	Button buOptions;
	ContextMenuStrip cmOptions;
	ToolStripMenuItem tsmiAutomount;
	ToolStripMenuItem tsmiShowDebugLog;
	ToolStripMenuItem tsmiMinimizeToTray;
	ToolStripMenuItem tsmiReapplyLibUSBFilters;
	TextBox tbDebugLog;
	StatusBar sbStatus;
	StatusBarPanel sbpDeviceCount;
	StatusBarPanel sbpMountStatus;
	bool bAutomount { get { return tsmiAutomount.Checked; } }
	bool bShowDebugLog { get { return tsmiShowDebugLog.Checked; } }
	bool bMinimizeToTray { get { return tsmiMinimizeToTray.Checked; } }
	const int nHeightWithoutDebugLog = 125;
	const int nHeightWithDebugLog = 365;
	const int nDefaultWidth = 540;

	static IDeviceNotifier USBNotifier = DeviceNotifier.OpenDeviceNotifier();
	UsbDevice iPhoneUSBDevice;
	iPhoneWrapper iPhone;
	char cMountDriveLetter = char.MinValue;
	bool bDriveMounted { get { return (iPhoneUSBDevice != null); } }

	public iPhoneDiskApplication()
	{
		#region GUI preparation
		Text = "jPhone";
		MaximizeBox = false;
		Size = new Size(nDefaultWidth, nHeightWithoutDebugLog);
		FormBorderStyle = FormBorderStyle.FixedSingle;
		ShowIcon = true;
		iApplication = new Icon(GetType(), "jphone.icons.icon.ico");
		Icon = iApplication;
		FormClosing += new FormClosingEventHandler(iPhoneDiskApplication_FormClosing);
		SizeChanged += new EventHandler(iPhoneDiskApplication_SizeChanged);
		Show();

		niTrayIcon = new NotifyIcon();
		niTrayIcon.Text = "jPhone";
		niTrayIcon.Icon = Icon;
		niTrayIcon.Click += new EventHandler(niTrayIcon_Click);

		lbText = new Label();
		lbText.AutoSize = true;
		lbText.Location = new Point(10, 10);
		lbText.Text = "Select the iPhone, iPod Touch or iPad to mount:";

		cbDeviceList = new ComboBox();
		cbDeviceList.Location = new Point(lbText.Left + 5, lbText.Bottom);
		cbDeviceList.Width = 320;
		cbDeviceList.DropDownStyle = ComboBoxStyle.DropDownList;

		buMount = new Button();
		buMount.Location = new Point(cbDeviceList.Right + 15, cbDeviceList.Top - 3);
		buMount.Size = new Size(80, 25);
		buMount.Click += new EventHandler(buMount_Click);
		buMount.Enabled = false;

		cmOptions = new ContextMenuStrip();
		cmOptions.RenderMode = ToolStripRenderMode.System;
		cmOptions.ShowImageMargin = false;
		cmOptions.ShowCheckMargin = true;
		tsmiAutomount = new ToolStripMenuItem("Automount", null, (s, e) => { tsmiAutomount.Checked = !tsmiAutomount.Checked; });
		tsmiMinimizeToTray = new ToolStripMenuItem("Minimize to tray", null, (s, e) => { tsmiMinimizeToTray.Checked = !tsmiMinimizeToTray.Checked; });
		tsmiShowDebugLog = new ToolStripMenuItem("Show debug log", null, (s, e) =>
		{
			tsmiShowDebugLog.Checked = !tsmiShowDebugLog.Checked;
			if (bShowDebugLog) Height = nHeightWithDebugLog;
			else Height = nHeightWithoutDebugLog;
		});
		tsmiReapplyLibUSBFilters = new ToolStripMenuItem("Re-apply libusb filters", null, ReapplyLibUSBFilters_Click);
		cmOptions.Items.Add(tsmiAutomount);
		cmOptions.Items.Add(tsmiShowDebugLog);
		cmOptions.Items.Add(tsmiMinimizeToTray);
		cmOptions.Items.Add("-");
		cmOptions.Items.Add(tsmiReapplyLibUSBFilters);

		buOptions = new Button();
		buOptions.Location = new Point(buMount.Right + 5, buMount.Top);
		buOptions.Size = new Size(80, 25);
		buOptions.Text = "Options";
		buOptions.Click += (s, e) => { cmOptions.Show(PointToScreen(new Point(buOptions.Left, buOptions.Bottom))); };
	
		bool[] bOptions = GetRegistryOptions();
		tsmiAutomount.Checked = bOptions[0];
		tsmiShowDebugLog.Checked = bOptions[1]; 
		tsmiMinimizeToTray.Checked = bOptions[2];
		if (bShowDebugLog) Height = nHeightWithDebugLog;

		tbDebugLog = new TextBox();
		tbDebugLog.ReadOnly = true;
		tbDebugLog.Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Bottom | AnchorStyles.Right;
		tbDebugLog.Location = new Point(10, 75);
		tbDebugLog.Size = new Size(ClientSize.Width - 20, nHeightWithDebugLog - 145);
		tbDebugLog.Multiline = true;
		tbDebugLog.BorderStyle = BorderStyle.FixedSingle;
		tbDebugLog.ScrollBars = ScrollBars.Vertical;

		sbStatus = new StatusBar();
		sbStatus.Dock = DockStyle.Bottom;
		sbStatus.SizingGrip = false;
		sbStatus.ShowPanels = true;
		sbpDeviceCount = new StatusBarPanel();
		sbpDeviceCount.Width = 150;
		sbpDeviceCount.Alignment = HorizontalAlignment.Center;
		sbpMountStatus = new StatusBarPanel();
		sbpMountStatus.AutoSize = StatusBarPanelAutoSize.Spring;
		sbpMountStatus.Alignment = HorizontalAlignment.Center;
		sbStatus.Panels.Add(sbpDeviceCount);
		sbStatus.Panels.Add(sbpMountStatus);

		Controls.AddRange(new Control[] { lbText, cbDeviceList, buMount, buOptions, sbStatus, tbDebugLog });
		
		cbDeviceList.Select();
		#endregion

		Global.LogUpdated += new Global.LogEventHandler(Global_LogUpdated);
		USBNotifier.OnDeviceNotify += new EventHandler<DeviceNotifyEventArgs>(USBNotifier_OnDeviceNotify);

		Global.Log("jPhone 1.0: iPhone mounting utility. Copyright 2010 Jonathan Bergknoff.\n");
		Global.Log("Shift-click the mount button to mount a jailbroken device as root.\n");
		Global.Log("http://www.getjpod.com/jphone\n");

		// Initialize everything to an unmounted state.
		UnmountDevice();
		PopulateDeviceList();
		TryAutomount();
	}
	~iPhoneDiskApplication()
	{
		iApplication.Dispose();
	}

	private void PopulateDeviceList()
	{
		// If a drive is mounted, do nothing.
		if (bDriveMounted) return;

		string sSelected = null;
		if (cbDeviceList.SelectedItem != null)
			sSelected = ((UsbRegistry)((ComboBoxItem)cbDeviceList.SelectedItem).Item).SymbolicName;

		cbDeviceList.Items.Clear();

		#region Wake up and add all Apple libusb devices (vendor ID 0x05AC) to the combo box.
		UsbRegDeviceList RDL = UsbDevice.AllLibUsbDevices;
		foreach (UsbRegistry R in RDL)
		{
			if (R.Vid == 0x05AC)
			{
				// If it hasn't been spoken to yet, set configuration 3 so it
				// doesn't timeout and auto-disconnect.
				byte byConfig;
				UsbDevice D;
				R.Open(out D);
				if (!((IUsbDevice)D).GetConfiguration(out byConfig) || byConfig == 0)
					((IUsbDevice)D).SetConfiguration(3);

				cbDeviceList.Items.Add(new ComboBoxItem(R, R.DeviceProperties["FriendlyName"] + " (PID 0x" + R.Pid.ToString("X") + ")"));
			}
		}
		#endregion

		#region Re-select the item that used to be selected, if it's still in the list.
		if (cbDeviceList.Items.Count > 0)
		{
			cbDeviceList.SelectedIndex = 0;
			if (sSelected != null)
			{
				foreach (ComboBoxItem CBI in cbDeviceList.Items)
					if (((UsbRegistry)CBI.Item).SymbolicName == sSelected)
					{
						cbDeviceList.SelectedItem = CBI;
						break;
					}
			}
		}
		#endregion

		sbpDeviceCount.Text = cbDeviceList.Items.Count + " device" + (cbDeviceList.Items.Count != 1 ? "s" : "") + " found";

		buMount.Enabled = (cbDeviceList.Items.Count > 0);
	}
	private void UnmountDevice() { UnmountDevice(false); }
	private void UnmountDevice(bool bUnexpected)
	{
		if (cMountDriveLetter != char.MinValue) DokanNet.DokanUnmount(cMountDriveLetter);
		if (iPhone != null) iPhone.Shutdown(bUnexpected);
		iPhoneUSBDevice = null;
		iPhone = null;
		cMountDriveLetter = char.MinValue;
		buMount.Text = "Mount";
		tsmiReapplyLibUSBFilters.Enabled = true;
		sbpMountStatus.Text = "No device mounted";
		cbDeviceList.Enabled = true;
	}
	private void TryAutomount()
	{
		if (bAutomount && cbDeviceList.Items.Count == 1)
			MountDevice(false);
	}
	private void MountDevice(bool bAFC2)
	{
		if (cbDeviceList.SelectedItem != null && ((UsbRegistry)((ComboBoxItem)cbDeviceList.SelectedItem).Item).IsAlive)
		{
			cbDeviceList.Enabled = false;
			Application.DoEvents(); // Without this, combobox doesn't appear disabled until the iPhone comm. finishes.

			Global.Log("Attempting to mount" + (bAFC2 ? " (as root)" : "") + "...\n");

			try
			{
				sbpMountStatus.Text = "Negotiating with device...";
				((UsbRegistry)((ComboBoxItem)cbDeviceList.SelectedItem).Item).Open(out iPhoneUSBDevice);
				iPhone = new iPhoneWrapper(iPhoneUSBDevice, bAFC2);
			}
			catch (Exception ex)
			{
				Global.Log("Aborting because exception encountered:\n" + ex + "\n\n");
				UnmountDevice();
				PopulateDeviceList();
				return;
			}

			buMount.Text = "Unmount";
			tsmiReapplyLibUSBFilters.Enabled = false;

			#region  Find the first available drive letter. Skip A:\ and B:\.
			List<char> Letters = new List<char>();
			for (int i = 2; i < 26; i++)
				Letters.Add(Convert.ToChar((byte)('A' + i)));

			DriveInfo[] Drives = DriveInfo.GetDrives();
			foreach (DriveInfo DI in Drives)
				try { Letters.Remove(DI.Name[0]); }
				catch { }

			cMountDriveLetter = Letters[0];
			#endregion

			System.ComponentModel.BackgroundWorker DokanBW = new System.ComponentModel.BackgroundWorker();
			DokanBW.DoWork += new System.ComponentModel.DoWorkEventHandler(DokanBW_DoWork);
			DokanBW.WorkerSupportsCancellation = true;
			DokanBW.RunWorkerAsync(iPhone);

			sbpDeviceCount.Text = "";
			sbpMountStatus.Text = ((UsbRegistry)((ComboBoxItem)cbDeviceList.SelectedItem).Item).DeviceProperties["FriendlyName"] + " mounted on drive " + cMountDriveLetter + ":\\";
		}
	}
	private void buMount_Click(object sender, System.EventArgs e)
	{
		if (bDriveMounted)
		{
			UnmountDevice();
			PopulateDeviceList();
		}
		else
			MountDevice(Control.ModifierKeys == Keys.Shift);
	}
	private void USBNotifier_OnDeviceNotify(object sender, DeviceNotifyEventArgs e)
	{
		// Only interested in Apple devices.
		if (e.Device.IdVendor != 0x05AC) return;

		if (!bDriveMounted)
		{
			PopulateDeviceList();
			TryAutomount();
		}

		// If a drive is mounted and we get an event, check to see if the mounted device was
		// unexpectedly unplugged.
		else
		{
			if (!iPhoneUSBDevice.UsbRegistryInfo.IsAlive)
			{
				Global.Log("Unmounting unexpectedly.\n");
				UnmountDevice(true);
				PopulateDeviceList();
			}
		}
	}
	private void DokanBW_DoWork(object sender, System.ComponentModel.DoWorkEventArgs e)
	{
		DokanOptions DO = new DokanOptions();
		DO.DriveLetter = cMountDriveLetter;
		/////DO.MountPoint = cMountDriveLetter + ":\\";
		DO.VolumeLabel = ((iPhoneWrapper)e.Argument).DeviceName;
		/////DO.RemovableDrive = true;
		/////Global.Log("Dokan: Mounting \"" + DO.VolumeLabel + "\" as drive " + DO.MountPoint + ".\n");
		Global.Log("Dokan: Mounting \"" + DO.VolumeLabel + "\" as drive " + DO.DriveLetter + ":\\.\n");
		int nStatus = DokanNet.DokanMain(DO, (iPhoneWrapper)e.Argument);
		Global.Log("Dokan: Mount terminated.\n");
	}

	private void iPhoneDiskApplication_FormClosing(object sender, EventArgs e)
	{
		UnmountDevice();
		USBNotifier.OnDeviceNotify -= USBNotifier_OnDeviceNotify;
		USBNotifier.Enabled = false;
		SetRegistryOptions(new bool[] { bAutomount, bShowDebugLog, bMinimizeToTray });
	}
	private void iPhoneDiskApplication_SizeChanged(object sender, EventArgs e)
	{
		if (tsmiMinimizeToTray != null && bMinimizeToTray && WindowState == FormWindowState.Minimized)
		{
			ShowIcon = false;
			ShowInTaskbar = false;
			niTrayIcon.Visible = true;
		}
	}
	private void ReapplyLibUSBFilters_Click(object sender, EventArgs e)
	{
		try { System.Diagnostics.Process.Start(Path.GetDirectoryName(Application.ExecutablePath) + @"\applyfilter.exe"); }
		catch { }
	}
	private void niTrayIcon_Click(object sender, EventArgs e)
	{
		WindowState = FormWindowState.Normal;
		ShowInTaskbar = true;
		ShowIcon = true;
		Activate();
		tbDebugLog.SelectionStart = tbDebugLog.Text.Length;
		tbDebugLog.ScrollToCaret();
		niTrayIcon.Visible = false;
	}
	private void Global_LogUpdated(string sMessage, bool bIsContinuation)
	{
		sMessage = sMessage.Replace("\n", "\r\n");
		tbDebugLog.AppendText((bIsContinuation ? "" : "[" + DateTime.Now.ToString("HH:mm:ss") + "] ") + sMessage);
	}
	private bool[] GetRegistryOptions()
	{
		bool[] bOptions = new bool[] { false, true, true };
		RegistryKey RKey = Registry.CurrentUser.OpenSubKey("Software\\jPhone");
		if (RKey == null) return bOptions;

		bOptions[0] = Convert.ToBoolean(RKey.GetValue("Automount", false));
		bOptions[1] = Convert.ToBoolean(RKey.GetValue("ShowDebugLog", true));
		bOptions[2] = Convert.ToBoolean(RKey.GetValue("MinimizeToTray", true));
		RKey.Close();
		return bOptions;
	}
	private void SetRegistryOptions(bool[] bOptions)
	{
		RegistryKey RKey = Registry.CurrentUser.CreateSubKey("Software\\jPhone");
		if (RKey == null) return;

		RKey.SetValue("Automount", bOptions[0]);
		RKey.SetValue("ShowDebugLog", bOptions[1]);
		RKey.SetValue("MinimizeToTray", bOptions[2]);
		RKey.Close();
	}

	public static void Main()
	{
		Application.EnableVisualStyles();

		try { DokanNet.DokanVersion(); }
		catch (DllNotFoundException)
		{
			MessageBox.Show("Error loading/using DokanNet.dll.", "jPhone", MessageBoxButtons.OK, MessageBoxIcon.Error);
			return;
		}

		Application.Run(new iPhoneDiskApplication());
		UsbDevice.Exit();
	}
}