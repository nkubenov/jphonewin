using System;
using System.IO;
using System.Xml;
using System.Collections;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.X509;
using Dokan;
using LibUsbDotNet;
using LibUsbDotNet.Main;
using Microsoft.Win32;

enum AFCFileMode
{
	//ReadOnly = 1,
	ReadWrite = 2,
	WriteOnly = 3,
	//NewReadWrite = 4,
	//AppendWriteOnly = 5,
	//AppendReadWrite = 6
}
enum AFCLockOperation : long
{
	CreateSharedLock = 0x00000005L,
	CreateExclusiveLock = 0x00000006L,
	Unlock = 0x0000000CL
}

class iPhoneWrapper : DokanOperations
{
	public const int nDefaultTimeout = 800;

	UsbDevice iPhoneUSBDevice;
	UsbEndpointReader iPhoneEndpointReader;
	UsbEndpointWriter iPhoneEndpointWriter;
	List<USBMUXConnection> MUXConnections;
	LockdownConnection Lockdown;
	AFCConnection AFC;
	NotificationProxyConnection NP;

	public Org.BouncyCastle.X509.X509Certificate RootCertificate, HostCertificate;
	public AsymmetricCipherKeyPair RootKey, HostKey;
	public string sHostID;
	public DateTime StartTime;

	public bool Usable
	{
		get
		{
			return !(iPhoneUSBDevice == null /* || iPhoneUSBDevice.UsbRegistryInfo.IsAlive == false */
					|| iPhoneEndpointReader == null || iPhoneEndpointWriter == null);
		}
	}
	static byte[] iPhoneVersionHeader()
	{
		byte[] bVersionHeader = new byte[20];
		MemoryStream MS = new System.IO.MemoryStream(bVersionHeader);
		BinaryWriter BW = new BinaryWriter(MS);
		BW.Seek(4, SeekOrigin.Begin);
		BW.Write(System.Net.IPAddress.HostToNetworkOrder((int)20));
		BW.Write(System.Net.IPAddress.HostToNetworkOrder((int)1));
		BW.Close();
		MS.Close();
		return bVersionHeader;
	}
	private string _DeviceName;
	private string _UniqueDeviceID;
	public string DeviceName { get { return _DeviceName; } }

	public iPhoneWrapper(UsbDevice USBDevice, bool bAFC2)
	{
		if (USBDevice == null)
			throw new Exception("Failed to create iPhone wrapper");

		StartTime = DateTime.UtcNow;

		iPhoneUSBDevice = USBDevice;
		MUXConnections = new List<USBMUXConnection>();

		IUsbDevice LibUsbDevice = iPhoneUSBDevice as IUsbDevice;
		if (!ReferenceEquals(LibUsbDevice, null))
		{
			// This is a "whole" USB device. Before it can be used, 
			// the desired configuration and interface must be selected.

			// Select config #3
			LibUsbDevice.SetConfiguration(3);

			// Claim interface #1.
			LibUsbDevice.ClaimInterface(1);
		}

		// Open read endpoint 5.
		iPhoneEndpointReader = iPhoneUSBDevice.OpenEndpointReader(ReadEndpointID.Ep05);

		// Open write endpoint 4.
		iPhoneEndpointWriter = iPhoneUSBDevice.OpenEndpointWriter(WriteEndpointID.Ep04);

		// Say hello to the device and set up lockdown.
		if (!Initialize())
			throw new Exception("Couldn't initialize iPhone");

		// Try to start AFC2. If it doesn't work (not jailbroken), start AFC.
		int nAFCPort = 0;
		if (bAFC2)
		{
			try { nAFCPort = Lockdown.StartService("com.apple.afc2"); }
			catch
			{
				nAFCPort = Lockdown.StartService("com.apple.afc");
			}

			if (nAFCPort != 0)
			{
				AFC = new AFCConnection(this, 5, (ushort)nAFCPort);
				MUXConnections.Add(AFC);
			}
		}
		else
		{
			nAFCPort = Lockdown.StartService("com.apple.afc");
			AFC = new AFCConnection(this, 5, (ushort)nAFCPort);
			MUXConnections.Add(AFC);
		}

		int nNPPort = Lockdown.StartService("com.apple.mobile.notification_proxy");
		NP = new NotificationProxyConnection(this, 6, (ushort)nNPPort);
		MUXConnections.Add(NP);

		/*
		Global.Log("Writing out SQL post-processing commands... ");
		try
		{
			string sSQLCommands = Lockdown.GetSQLPostProcessCommands();
			long nHandle = AFC.OpenFile("/SQLCommands", AFCFileMode.WriteOnly);
			AFC.SetFileLength(nHandle, 0);
			AFC.WriteFile(nHandle, System.Text.Encoding.UTF8.GetBytes("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<plist>\n"));
			AFC.WriteFile(nHandle, System.Text.Encoding.UTF8.GetBytes(sSQLCommands));
			AFC.WriteFile(nHandle, System.Text.Encoding.UTF8.GetBytes("\n</plist>"));
			AFC.CloseFile(nHandle);
			Global.Log("success!\n", true);
		}
		catch { Global.Log("failed!\n", true); }
		*/

		Global.Log("Shutting down lockdownd (don't need it anymore).\n");
		try { Lockdown.CloseConnection(); } catch { }
		MUXConnections.Remove(Lockdown);
	}

	public void Shutdown(bool bUnexpected)
	{
		Global.Log("Shutting down iPhoneWrapper\n");

		// If device was unexpectedly removed (unplugged), don't try to send
		// goodbye packets.
		if (!bUnexpected)
		{
			foreach (USBMUXConnection C in MUXConnections)
			{
				try { C.CloseConnection(); }
				catch { }
			}
		}

		try
		{
			if (iPhoneUSBDevice != null)
			{
				if (iPhoneUSBDevice.UsbRegistryInfo.IsAlive)
				{
					//iPhoneEndpointReader.ReadFlush();

					IUsbDevice LibUsbDevice = iPhoneUSBDevice as IUsbDevice;
					if (!ReferenceEquals(LibUsbDevice, null))
					{
						// Release interface #1.
						LibUsbDevice.ReleaseInterface(1);
					}

					iPhoneUSBDevice.Close();
				}

				iPhoneUSBDevice = null;
				iPhoneEndpointReader = null;
				iPhoneEndpointWriter = null;
			}
		}
		catch { }
	}

	private bool Initialize()
	{
		if (!Usable) return false;

		ErrorCode EC = ErrorCode.None;
		int nBytesWritten, nBytesRead;

		try
		{
			// Flush the device by reading until there's nothing left to read.
			byte[] byBuffer = new byte[1024];
			while (true)
			{
				iPhoneEndpointReader.Read(byBuffer, 10, out nBytesRead);
				if (nBytesRead == 0 || EC != ErrorCode.None) break;
			}

			Global.Log("Saying hi to device... ");
			EC = iPhoneEndpointWriter.Write(iPhoneVersionHeader(), nDefaultTimeout, out nBytesWritten);
			if (EC != ErrorCode.None) throw new Exception(UsbDevice.LastErrorString);
			if (nBytesWritten != 20) throw new Exception("<20 bytes written. 20 expected.");

			// If the device hasn't sent data in the last nDefaultTimeout milliseconds,
			// a timeout error (ec = IoTimedOut) will occur.
			EC = iPhoneEndpointReader.Read(byBuffer, nDefaultTimeout, out nBytesRead);
			if (EC != ErrorCode.None)
			{
				Global.Log("failed! Is the device currently locked by a passcode? If not, replug it.\n", true);
				throw new Exception(UsbDevice.LastErrorString);
			}

			if (nBytesRead != 20)
			{
				Global.Log("failed!\n", true);
				throw new Exception("Device won't talk. Re-plug it.");
			}

			Global.Log("success!\n", true);

			int nTemp = 0;
			MemoryStream MS = new MemoryStream(byBuffer);
			BinaryReader BR = new BinaryReader(MS);
			MS.Seek(8, SeekOrigin.Begin);
			nTemp = System.Net.IPAddress.NetworkToHostOrder(BR.ReadInt32());
			if (nTemp != 1) throw new Exception("iPhone major version != 1");
			nTemp = System.Net.IPAddress.NetworkToHostOrder(BR.ReadInt32());
			if (nTemp != 0) throw new Exception("iPhone minor version != 1");
			BR.Close();
			MS.Close();
		}
		catch (Exception ex)
		{
			Global.Log((EC != ErrorCode.None ? EC + ":" : String.Empty) + ex.Message + "\n");
			return false;
		}

		Global.Log("Starting up lockdownd... ");
		try { Lockdown = new LockdownConnection(this); }
		catch (Exception e)
		{
			Global.Log("failed!\n", true);
			throw e;
		}
		MUXConnections.Add(Lockdown);
		Global.Log("success!\n", true);

		_DeviceName = Lockdown.GetDeviceName();
		_UniqueDeviceID = Lockdown.GetUniqueDeviceID();

		#region Preparation of cryptography stuff
		if (LoadCryptoStuffFromRegistry() == false)
		{
			Global.Log("Haven't seen this device before. Creating new RSA keys.\n");

			// First generate "root" and "host" private keys and X.509 certificates.
			X509V3CertificateGenerator RootCG = new X509V3CertificateGenerator();
			Org.BouncyCastle.Crypto.Generators.RsaKeyPairGenerator RootRKPG = new Org.BouncyCastle.Crypto.Generators.RsaKeyPairGenerator();
			RootRKPG.Init(new KeyGenerationParameters(new Org.BouncyCastle.Security.SecureRandom(), 1024));
			Global.Log("Generating RSA key pair for root... ");
			RootKey = RootRKPG.GenerateKeyPair();
			Global.Log("success!\n", true);

			/*System.Security.Cryptography.X509Certificates.X509Certificate C = new System.Security.Cryptography.X509Certificates.X509Certificate();
			RootCG.SetPublicKey(RootKey.Public);
			RootCG.SetSerialNumber(Org.BouncyCastle.Math.BigInteger.One);
			RootCG.SetNotBefore(StartTime);
			RootCG.SetNotAfter(new DateTime(StartTime.Ticks + ((long)10000000 * 60 * 60 * 24 * 365 * 10)));
			// Issuer and subject stuff are irrelevant but BouncyCastle won't accept null inputs.
			RootCG.SetIssuerDN(new Org.BouncyCastle.Asn1.X509.X509Name(new ArrayList(), new ArrayList()));
			RootCG.SetSubjectDN(new Org.BouncyCastle.Asn1.X509.X509Name(new ArrayList(), new ArrayList()));
			RootCG.SetSignatureAlgorithm("SHA1WithRSAEncryption");
			RootCG.AddExtension(Org.BouncyCastle.Asn1.X509.X509Extensions.BasicConstraints, true, new Org.BouncyCastle.Asn1.X509.BasicConstraints(true));
			//Org.BouncyCastle.Asn1.X509.SubjectKeyIdentifier RootSKI = new Org.BouncyCastle.X509.Extension.SubjectKeyIdentifierStructure(RootKey.Public);
			//RootCG.AddExtension(Org.BouncyCastle.Asn1.X509.X509Extensions.SubjectKeyIdentifier, false, RootSKI);
			RootCertificate = RootCG.Generate(RootKey.Private);*/

			System.Security.Cryptography.X509Certificates.X509Certificate C = new System.Security.Cryptography.X509Certificates.X509Certificate();
			RootCG.SetPublicKey(RootKey.Public);
			RootCG.SetSerialNumber(Org.BouncyCastle.Math.BigInteger.Zero);
			RootCG.SetNotBefore(StartTime);
			RootCG.SetNotAfter(new DateTime(StartTime.Ticks + ((long)10000000 * 60 * 60 * 24 * 365 * 10)));
			RootCG.SetSignatureAlgorithm("SHA1WithRSAEncryption");
			RootCG.AddExtension(Org.BouncyCastle.Asn1.X509.X509Extensions.BasicConstraints, true, new Org.BouncyCastle.Asn1.X509.BasicConstraints(true));
			RootCertificate = RootCG.Generate(RootKey.Private);

			X509V3CertificateGenerator HostCG = new X509V3CertificateGenerator();
			Org.BouncyCastle.Crypto.Generators.RsaKeyPairGenerator HostRKPG = new Org.BouncyCastle.Crypto.Generators.RsaKeyPairGenerator();
			HostRKPG.Init(new KeyGenerationParameters(new Org.BouncyCastle.Security.SecureRandom(), 1024));
			Global.Log("Generating RSA key pair for host... ");
			HostKey = HostRKPG.GenerateKeyPair();
			Global.Log("success!\n", true);

			HostCG.SetPublicKey(HostKey.Public);
			HostCG.SetSerialNumber(Org.BouncyCastle.Math.BigInteger.Zero);
			HostCG.SetNotBefore(RootCertificate.NotBefore);
			HostCG.SetNotAfter(RootCertificate.NotAfter);
			//HostCG.SetIssuerDN(new Org.BouncyCastle.Asn1.X509.X509Name(new ArrayList(), new ArrayList()));
			//HostCG.SetSubjectDN(new Org.BouncyCastle.Asn1.X509.X509Name(new ArrayList(), new ArrayList()));
			HostCG.SetSignatureAlgorithm("SHA1WithRSAEncryption");
			HostCG.AddExtension(Org.BouncyCastle.Asn1.X509.X509Extensions.BasicConstraints, true, new Org.BouncyCastle.Asn1.X509.BasicConstraints(false));
			//Org.BouncyCastle.Asn1.X509.SubjectKeyIdentifier HostSKI = new Org.BouncyCastle.X509.Extension.SubjectKeyIdentifierStructure(HostKey.Public);
			//HostCG.AddExtension(Org.BouncyCastle.Asn1.X509.X509Extensions.SubjectKeyIdentifier, false, HostSKI);
			HostCG.AddExtension(Org.BouncyCastle.Asn1.X509.X509Extensions.KeyUsage, true,
					new Org.BouncyCastle.Asn1.X509.KeyUsage(Org.BouncyCastle.Asn1.X509.KeyUsage.KeyEncipherment | Org.BouncyCastle.Asn1.X509.KeyUsage.DigitalSignature));
			HostCertificate = HostCG.Generate(RootKey.Private);
		}
		else
			Global.Log("Loaded RSA stuff from registry.\n");
		#endregion

		try { Lockdown.Authenticate(); }
		catch (Exception e)
		{
			Global.Log("Exception encountered during authentication:\n" + e);
			Shutdown(false);
			return false;
		}

		return true;
	}

	public void CommitCryptoStuffToRegistry()
	{
		Org.BouncyCastle.OpenSsl.PemWriter PW;
		MemoryStream MS;
		TextWriter TW;

		if (sHostID == null || RootKey == null || RootCertificate == null
				|| HostKey == null || HostCertificate == null)
			return;

		RegistryKey RKey = Registry.CurrentUser.CreateSubKey("Software\\jPhone\\" + _UniqueDeviceID);
		if (RKey != null)
		{
			RKey.SetValue("HostID", sHostID);

			MS = new MemoryStream();
			TW = new StreamWriter(MS);
			PW = new Org.BouncyCastle.OpenSsl.PemWriter(TW);
			PW.WriteObject(RootKey);
			RKey.SetValue("RootKey", MS.GetBuffer());
			TW.Close();
			MS.Close();

			MS = new MemoryStream();
			TW = new StreamWriter(MS);
			PW = new Org.BouncyCastle.OpenSsl.PemWriter(TW);
			PW.WriteObject(RootCertificate);
			RKey.SetValue("RootCert", MS.GetBuffer());
			TW.Close();
			MS.Close();

			MS = new MemoryStream();
			TW = new StreamWriter(MS);
			PW = new Org.BouncyCastle.OpenSsl.PemWriter(TW);
			PW.WriteObject(HostKey);
			RKey.SetValue("HostKey", MS.GetBuffer());
			TW.Close();
			MS.Close();

			MS = new MemoryStream();
			TW = new StreamWriter(MS);
			PW = new Org.BouncyCastle.OpenSsl.PemWriter(TW);
			PW.WriteObject(HostCertificate);
			RKey.SetValue("HostCert", MS.GetBuffer());
			TW.Close();
			MS.Close();

			RKey.Close();
		}
	}

	private bool LoadCryptoStuffFromRegistry()
	{
		RegistryKey RKey = Registry.CurrentUser.OpenSubKey("Software\\jPhone\\" + _UniqueDeviceID);
		if (RKey == null) return false;
		if (RKey.GetValue("HostID") == null || RKey.GetValue("RootKey") == null
			|| RKey.GetValue("RootCert") == null || RKey.GetValue("HostKey") == null
			|| RKey.GetValue("HostCert") == null)
		{
			RKey.Close();
			Registry.CurrentUser.DeleteSubKey("Software\\jPhone\\" + _UniqueDeviceID, false);
			return false;
		}

		sHostID = (string)RKey.GetValue("HostID");

		MemoryStream MS;
		TextReader TR;
		Org.BouncyCastle.OpenSsl.PemReader PR;
		byte[] bBuffer;

		bBuffer = (byte[])RKey.GetValue("RootKey");
		MS = new MemoryStream(bBuffer);
		TR = new StreamReader(MS);
		PR = new Org.BouncyCastle.OpenSsl.PemReader(TR);
		RootKey = (AsymmetricCipherKeyPair)PR.ReadObject();
		TR.Close();
		MS.Close();

		bBuffer = (byte[])RKey.GetValue("RootCert");
		MS = new MemoryStream(bBuffer);
		TR = new StreamReader(MS);
		PR = new Org.BouncyCastle.OpenSsl.PemReader(TR);
		RootCertificate = (Org.BouncyCastle.X509.X509Certificate)PR.ReadObject();
		TR.Close();
		MS.Close();

		bBuffer = (byte[])RKey.GetValue("HostKey");
		MS = new MemoryStream(bBuffer);
		TR = new StreamReader(MS);
		PR = new Org.BouncyCastle.OpenSsl.PemReader(TR);
		HostKey = (AsymmetricCipherKeyPair)PR.ReadObject();
		TR.Close();
		MS.Close();

		bBuffer = (byte[])RKey.GetValue("HostCert");
		MS = new MemoryStream(bBuffer);
		TR = new StreamReader(MS);
		PR = new Org.BouncyCastle.OpenSsl.PemReader(TR);
		HostCertificate = (Org.BouncyCastle.X509.X509Certificate)PR.ReadObject();
		TR.Close();
		MS.Close();
		
		RKey.Close();
		return true;
	}

	// Send raw data to the phone.
	// Returns the number of bytes sent, or -1 on error.
	public int SendToiPhone(byte[] byData)
	{
		if (!Usable) throw new Exception("iPhone not usable in SendToiPhone.");
		if (byData.Length == 0) return 0;

		ErrorCode EC = ErrorCode.None;
		int nBytesWritten;

		try
		{
			EC = iPhoneEndpointWriter.Write(byData, nDefaultTimeout, out nBytesWritten);
			if (EC != ErrorCode.None) throw new Exception(UsbDevice.LastErrorString);
			if (nBytesWritten != byData.Length) throw new Exception("Tried to write " + byData.Length + " bytes, only wrote " + nBytesWritten + ".");
		}
		catch (Exception ex)
		{
			Global.Log("In iPhoneWrapper::SendToiPhone...\n");
			Global.Log((EC != ErrorCode.None ? EC + ":" : String.Empty) + ex.Message + "\n");
			throw new Exception("Encountered a problem in SendToiPhone.");
		}

		return nBytesWritten;
	}

	// Receive raw data from the phone. nTimeout in milliseconds.
	// Returns byte array containing the raw data.
	public byte[] ReceiveFromiPhone()
	{
		if (!Usable) return null;

		ErrorCode EC = ErrorCode.None;
		int nBytesRead;

		byte[] byBuffer = new byte[64 * 1024];
		try
		{
			EC = iPhoneEndpointReader.Read(byBuffer, 0, byBuffer.Length, nDefaultTimeout, out nBytesRead);
			if (EC != ErrorCode.None) throw new Exception(UsbDevice.LastErrorString);
		}
		catch (Exception ex)
		{
			Global.Log("\nIn iPhoneWrapper::ReceiveFromiPhone...\n");
			Global.Log((EC != ErrorCode.None ? EC + ":" : String.Empty) + ex.Message + "\n");
			return null;
		}

		Array.Resize(ref byBuffer, nBytesRead);
		return byBuffer;
	}

	// If a MUX packet is received by the wrong connection, the connection
	// will send it here to be redirected to the correct connection ("correct"
	// determined based on source & destination ports).
	public void RedirectMUXPacket(byte[] byPacket)
	{
		short nPacketSourcePort = System.Net.IPAddress.NetworkToHostOrder((short)BitConverter.ToInt16(byPacket, 0x0A));
		short nPacketDestPort = System.Net.IPAddress.NetworkToHostOrder((short)BitConverter.ToInt16(byPacket, 0x08));

		foreach (USBMUXConnection C in MUXConnections)
		{
			if (C.OnPorts(nPacketSourcePort, nPacketDestPort))
			{
				C.BufferPacket(byPacket);
				break;
			}
		}
	}

	public static string GenerateHostID()
	{
		const string sChoices = "ABCDEF0123456789";
		Random nRandom = new Random((int)DateTime.Now.Ticks);

		string sID = "";
		for (int i = 0; i < 36; i++)
		{
			if (i == 8 || i == 13 || i == 18 || i == 23)
			{
				sID += "-";
				continue;
			}

			sID += sChoices[nRandom.Next(16)];
		}

		return sID;
	}

	#region Dokan implementation
	public int Cleanup(string sPath, DokanFileInfo DFI)
	{
		sPath = sPath.Replace("\\", "/");
		if (DFI.Context != null)
		{
			try { AFC.CloseFile((long)DFI.Context); }
			catch (Exception) { return -1; }
		}

		if (DFI.DeleteOnClose)
		{
			try { AFC.RemovePath(sPath); }
			catch (Exception) { return -1; }
		}

		return 0;
	}

	public int CloseFile(string sPath, DokanFileInfo DFI)
	{
		return 0;
	}

	public int CreateDirectory(string sPath, DokanFileInfo DFI)
	{
		sPath = sPath.Replace("\\", "/");
		//Global.Log(System.Reflection.MethodBase.GetCurrentMethod().Name + "({0})\n", sPath);
		try { AFC.MakeDirectory(sPath); }
		catch (Exception) { Global.Log("mkdir exception\n"); return -1; }
		DFI.IsDirectory = true;
		return 0;
	}

	public int CreateFile(string sPath, System.IO.FileAccess FA, System.IO.FileShare FS, System.IO.FileMode FM,
										System.IO.FileOptions FO, DokanFileInfo DFI)
	{
		bool bFileExists = true;
		string sFileInfo = null;
		sPath = sPath.Replace("\\", "/");
		try { sFileInfo = AFC.GetFileInfo(sPath); }
		catch (FileNotFoundException)
		{
			// File not found is only fatal under certain circumstances.
			bFileExists = false;
			if (FM == FileMode.Open || FM == FileMode.Truncate)
				return -DokanNet.ERROR_FILE_NOT_FOUND;
		}
		catch (Exception) { return -1; }

		if (bFileExists)
		{
			if (FM == FileMode.CreateNew)
				return -DokanNet.ERROR_FILE_EXISTS;

			string[] sFileInfoParts = sFileInfo.Split(new char[] { '\x0' });
			string sFileType = null;
			for (int i = 0; i < sFileInfoParts.Length; i++)
			{
				if (sFileInfoParts[i] == "st_ifmt" && i < (sFileInfoParts.Length - 1))
					sFileType = sFileInfoParts[i + 1];
			}

			if (sFileType == "S_IFDIR" || sFileType == "S_IFLNK")
				DFI.IsDirectory = true;
			else
			{
				long nFileHandle;
				if (FM == FileMode.Create)
					try { AFC.RemovePath(sPath); }
					catch { }

				// Windows Explorer in Win7 was CreateFile-ing with FileAccess.Write, causing
				// files to get wiped out. I don't know if it's necessary under any circumstances
				// to use AFCFileMode.WriteOnly, so I will always use AFCFileMode.ReadWrite.
				try { nFileHandle = AFC.OpenFile(sPath, AFCFileMode.ReadWrite); } //(FA == FileAccess.Write ? AFCFileMode.WriteOnly : AFCFileMode.ReadWrite)); }
				catch (Exception e) { Global.Log(e.Message + "\n"); return -1; }
				DFI.Context = nFileHandle;
			}
		}
		else
		{
			// File doesn't exist, then try to create it.
			long nFileHandle;
			try { nFileHandle = AFC.OpenFile(sPath, AFCFileMode.ReadWrite); } //(FA == FileAccess.Write ? AFCFileMode.WriteOnly : AFCFileMode.ReadWrite)); }
			catch (Exception e) { Global.Log(e.Message + "\n"); return -1; }
			DFI.Context = nFileHandle;
		}

		return 0;
	}

	public int DeleteDirectory(string sPath, DokanFileInfo DFI)
	{
		string[] sFiles;
		sPath = sPath.Replace("\\", "/");
		try { sFiles = AFC.ListDirectory(sPath); }
		catch (Exception) { Global.Log("ListDirectory exception\n"); return -1; }
		if (sFiles.Length > 3) return -145; // ".", ".." and a null string. ERROR_DIR_NOT_EMPTY
		return 0;
	}

	public int DeleteFile(string sPath, DokanFileInfo DFI)
	{
		sPath = sPath.Replace("\\", "/");
		try { AFC.GetFileInfo(sPath); }
		catch (FileNotFoundException) { return -DokanNet.ERROR_FILE_NOT_FOUND; }
		catch (Exception) { return -1; }
		return 0;
	}

	public int FlushFileBuffers(string sPath, DokanFileInfo DFI)
	{
		return 0;
	}

	public int FindFiles(string sPath, System.Collections.ArrayList FoundFiles, DokanFileInfo DFI)
	{
		sPath = sPath.Replace("\\", "/");
		string[] sDirectoryListing;

		try { sDirectoryListing = AFC.ListDirectory(sPath); }
		catch (FileNotFoundException) { return -DokanNet.ERROR_PATH_NOT_FOUND; }
		catch (Exception) { return -1; }

		sPath += "/";
		foreach (string sItem in sDirectoryListing)
		{
			if (sItem == "." || sItem == ".." || String.IsNullOrEmpty(sItem)) continue;

			string sFileInfo;
			try { sFileInfo = AFC.GetFileInfo(sPath + sItem); }
			catch (Exception) { continue; }
			string[] sFileInfoParts = sFileInfo.Split(new char[] { '\x0' });
			string sFileType = null;
			string sFileLength = null;
			for (int i = 0; i < sFileInfoParts.Length; i++)
			{
				if (sFileInfoParts[i] == "st_size" && i < (sFileInfoParts.Length - 1))
					sFileLength = sFileInfoParts[i + 1];
				else if (sFileInfoParts[i] == "st_ifmt" && i < (sFileInfoParts.Length - 1))
					sFileType = sFileInfoParts[i + 1];
			}

			FileInformation FI = new FileInformation();
			FI.FileName = sItem;
			FI.LastAccessTime = DateTime.Now;
			FI.LastWriteTime = DateTime.Now;
			FI.CreationTime = DateTime.Now;
			if (sFileLength != null) FI.Length = long.Parse(sFileLength);

			switch (sFileType)
			{
				case "S_IFLNK":
				case "S_IFDIR":
					FI.Length = 0;
					FI.Attributes = FileAttributes.Directory;
					break;

				case "S_IFREG":
					FI.Attributes = FileAttributes.Normal;
					break;

				default:
					FI.Attributes = FileAttributes.Normal;
					break;
			}

			FoundFiles.Add(FI);
		}

		return 0;
	}

	public int GetFileInformation(string sPath, FileInformation FI, DokanFileInfo DFI)
	{
		string sFileInfo;
		sPath = sPath.Replace("\\", "/");

		FI.Attributes = System.IO.FileAttributes.Directory;
		FI.LastAccessTime = DateTime.Now;
		FI.LastWriteTime = DateTime.Now;
		FI.CreationTime = DateTime.Now;
		FI.Length = 0;

		try { sFileInfo = AFC.GetFileInfo(sPath); }
		catch (Exception) { return 0; }
		string[] sFileInfoParts = sFileInfo.Split(new char[] { '\x0' });
		string sFileType = null;
		string sFileLength = null;
		for (int i = 0; i < sFileInfoParts.Length; i++)
		{
			if (sFileInfoParts[i] == "st_size" && i < (sFileInfoParts.Length - 1))
				sFileLength = sFileInfoParts[i + 1];
			else if (sFileInfoParts[i] == "st_ifmt" && i < (sFileInfoParts.Length - 1))
				sFileType = sFileInfoParts[i + 1];
		}

		FI.LastAccessTime = DateTime.Now;
		FI.LastWriteTime = DateTime.Now;
		FI.CreationTime = DateTime.Now;
		if (sFileLength != null) FI.Length = long.Parse(sFileLength);

		switch (sFileType)
		{
			case "S_IFLNK":
			case "S_IFDIR":
				FI.Attributes = FileAttributes.Directory;
				break;

			case "S_IFREG":
				FI.Attributes = FileAttributes.Normal;
				break;

			default:
				FI.Attributes = FileAttributes.Normal;
				break;
		}

		return 0;
	}

	public int LockFile(string sPath, long nOffset, long nLength, DokanFileInfo DFI)
	{
		const int nTries = 3000;

		if (sPath.EndsWith("com.apple.itunes.lock_sync"))
		{
			Global.Log("Sending SyncWillStart notification.\n");
			NP.PostNotification(NotificationProxyConnection.SyncWillStart);
			Global.Log("Sending SyncLockRequest notification.\n");
			NP.PostNotification(NotificationProxyConnection.SyncLockRequest);
			for (int i = 0; i < nTries; i++)
			{
				try { AFC.LockFile((long)DFI.Context, AFCLockOperation.CreateExclusiveLock); }
				catch (InvalidOperationException)
				{
					if (i % 500 == 499) Global.Log("No luck after " + (i + 1).ToString() + " attempts to lock sync file.\n");
					continue;
				}
				catch
				{
					Global.Log("Failed trying to lock sync file.\n");
					break;
				}

				Global.Log("Sending SyncDidStart notification.\n");
				NP.PostNotification(NotificationProxyConnection.SyncDidStart);
				return 0;
			}

			NP.PostNotification(NotificationProxyConnection.SyncFailedToStart);
		}
		/*else if (sPath.EndsWith("com.apple.itdbprep.postprocess.lock"))
		{
			Global.Log("Sending PostProcessingWillBegin notification.\n");
			NP.PostNotification(NotificationProxyConnection.PostProcessingWillBegin);
		}*/

		return 0;
	}

	public int MoveFile(string sPath, string sNewPath, bool bReplace, DokanFileInfo DFI)
	{
		sPath = sPath.Replace("\\", "/");
		sNewPath = sNewPath.Replace("\\", "/");

		try { AFC.RenamePath(sPath, sNewPath); }
		catch (Exception) { Global.Log("MoveFile exception\n"); return -1; }

		return 0;
	}

	public int OpenDirectory(string sPath, DokanFileInfo DFI)
	{
		sPath = sPath.Replace("\\", "/");
		try { AFC.GetFileInfo(sPath); }
		catch (FileNotFoundException) { return -DokanNet.ERROR_PATH_NOT_FOUND; }
		catch (Exception) { return -1; }
		DFI.IsDirectory = true;
		return 0;
	}

	public int ReadFile(string sPath, byte[] bOutBuffer, ref uint nBytesRead, long nOffset, DokanFileInfo DFI)
	{
		if (DFI.Context == null) return -1;

		try { AFC.SeekFile((long)DFI.Context, nOffset); }
		catch (Exception) { return -1; }

		byte[] bReceivedData;
		try { bReceivedData = AFC.ReadFile((long)DFI.Context, bOutBuffer.LongLength); }
		catch (Exception e) { Global.Log(e.Message + "\n"); return -1; }

		nBytesRead = (uint)bReceivedData.Length;
		Array.Copy(bReceivedData, bOutBuffer, (nBytesRead < bOutBuffer.Length ? nBytesRead : (uint)bOutBuffer.Length));

		return 0;
	}

	public int SetEndOfFile(string sPath, long nLength, DokanFileInfo DFI)
	{
		if (DFI.Context == null) return -1;

		try { AFC.SetFileLength((long)DFI.Context, nLength); }
		catch (Exception) { return -1; }
		return 0;
	}

	public int SetAllocationSize(string sPath, long nLength, DokanFileInfo DFI)
	{
		return 0;
	}

	public int SetFileAttributes(string sPath, System.IO.FileAttributes FA, DokanFileInfo DFI)
	{
		return -1;
	}

	public int SetFileTime(string sPath, DateTime ctime, DateTime atime, DateTime mtime, DokanFileInfo DFI)
	{
		return -1;
	}

	public int UnlockFile(string sPath, long offset, long length, DokanFileInfo DFI)
	{
		if (sPath.EndsWith("com.apple.itunes.lock_sync"))
		{
			AFC.LockFile((long)DFI.Context, AFCLockOperation.Unlock);
			Global.Log("Sending SyncDidFinish notification.\n");
			NP.PostNotification(NotificationProxyConnection.SyncDidFinish);
		}
		/*else if (sPath.EndsWith("com.apple.itdbprep.postprocess.lock"))
		{
			Global.Log("Sending PostProcessingDidEnd notification.\n");
			NP.PostNotification(NotificationProxyConnection.PostProcessingDidEnd);
		}*/

		return 0;
	}

	public int Unmount(DokanFileInfo DFI)
	{
		return 0;
	}

	public int GetDiskFreeSpace(ref ulong nFreeAvailable, ref ulong nTotal, ref ulong nTotalFree, DokanFileInfo DFI)
	{
		// URGENT TODO FIXME: on jailbroken devices, this does not return the correct information.
		try
		{
			string sInfoString = AFC.GetDeviceInfo();
			if (String.IsNullOrEmpty(sInfoString))
				throw new Exception();

			string[] sInfoStrings = sInfoString.Split(new char[] { '\x0' });
			nTotal = ulong.Parse(sInfoStrings[3]);
			nFreeAvailable = ulong.Parse(sInfoStrings[5]);
			nTotalFree = ulong.Parse(sInfoStrings[5]);
		}
		catch (Exception)
		{
			nTotal = 2;
			nFreeAvailable = 1;
			nTotalFree = 1;
		}

		return 0;
	}

	public int WriteFile(string sPath, byte[] bBuffer, ref uint nBytesWritten, long nOffset, DokanFileInfo DFI)
	{
		if (DFI.Context == null) return -1;

		try { AFC.SeekFile((long)DFI.Context, nOffset); }
		catch (Exception) { return -1; }

		try { nBytesWritten = AFC.WriteFile((long)DFI.Context, bBuffer); }
		catch (Exception e) { Global.Log(e.Message + "\n"); return -1; }

		return 0;
	}
	#endregion
}

abstract class USBMUXConnection
{
	protected iPhoneWrapper iPhone;
	ushort SourcePort, DestPort;
	uint SentCount, ReceivedCount;
	byte[] byPacketHeader;

	// If a packet intended for this connection was received by another
	// USBMUXConnection, it will queue up the data in here
	Queue<byte[]> BufferedPacketsWaiting;

	// A USBMUX connection is created for each port that will be used for communication.
	// For instance, one will be created on port 0xF27E for the lockdown protocol.
	// Communications are all prefaced by a TCP-like packet header that is managed on a
	// per-connection basis by this class.
	public USBMUXConnection(iPhoneWrapper IPW, ushort SPort, ushort DPort)
	{
		if (IPW == null || !IPW.Usable) throw new Exception("No device ready in USBMUXConnection constructor.");
		if (SPort == 0 || DPort == 0) throw new Exception("Need non-zero ports to create USBMUXConnection");

		iPhone = IPW;
		BufferedPacketsWaiting = new Queue<byte[]>();
		SourcePort = SPort;
		DestPort = DPort;
		SentCount = 0;
		ReceivedCount = 0;

		// Initialize packet header for SYN step of handshake.
		byPacketHeader = new byte[28];
		MemoryStream MS = new MemoryStream(byPacketHeader);
		BinaryWriter BW = new BinaryWriter(MS);
		BW.Write(System.Net.IPAddress.HostToNetworkOrder((int)6)); // Type
		BW.Write(System.Net.IPAddress.HostToNetworkOrder((int)28)); // Length
		BW.Write(System.Net.IPAddress.HostToNetworkOrder((short)SourcePort)); // Source port
		BW.Write(System.Net.IPAddress.HostToNetworkOrder((short)DestPort)); // Destination port
		BW.Write(System.Net.IPAddress.HostToNetworkOrder((int)SentCount)); // Self Count
		BW.Write(System.Net.IPAddress.HostToNetworkOrder((int)ReceivedCount)); // OCnt
		BW.Write((byte)0x50); // Offset
		BW.Write((byte)2); // TCP Flag = SYN
		BW.Write(System.Net.IPAddress.HostToNetworkOrder((short)0x0200)); // Window size
		BW.Seek(2, SeekOrigin.Current); // Always zero
		BW.Write(System.Net.IPAddress.HostToNetworkOrder((short)28)); // Length16
		BW.Close();
		MS.Close();

		// Initiate handshake: send SYN.
		if (SendHeader() < 0)
			throw new Exception("Failed to send SYN");

		// Continue handshake: receive SYNACK.
		byte[] byResponse = iPhone.ReceiveFromiPhone();
		if (byResponse == null || byResponse.Length != 28 || byResponse[0x15] != 0x12)
			throw new Exception("Expected SYNACK, got something else.");

		byPacketHeader[0x15] = 0x10;
		SentCount = 1;
		ReceivedCount = 1;
	}

	// Used to close the connection.
	protected void SetRST()
	{
		byPacketHeader[0x15] = 4;
	}

	public virtual void CloseConnection()
	{
		SetRST();
		try { SendHeader(); }
		catch (Exception) { Global.Log("Failed to send RST\n"); }
	}

	public bool OnPorts(short Source, short Dest) { return (Source == SourcePort && Dest == DestPort); }

	// Supplies no additional data, so it just sends a packet header.
	private int SendHeader() { return Send(null); }

	// Sends a packet to the iPhone made up of a packet header and bData.
	protected int Send(byte[] bData)
	{
		if (iPhone == null || !iPhone.Usable) throw new Exception("No device ready in USBMUXConnection constructor.");

		int nPacketLength = 28;
		byte[] byPacket;

		if (bData != null)
		{
			nPacketLength += bData.Length;
			byPacket = new byte[nPacketLength];
			Array.Copy(bData, 0, byPacket, 28, bData.Length);
		}
		else
			byPacket = new byte[28];

		Array.Copy(BitConverter.GetBytes(System.Net.IPAddress.HostToNetworkOrder((int)nPacketLength)), 0, byPacketHeader, 0x04, 4);
		Array.Copy(BitConverter.GetBytes(System.Net.IPAddress.HostToNetworkOrder((short)nPacketLength)), 0, byPacketHeader, 0x1A, 2);
		Array.Copy(BitConverter.GetBytes(System.Net.IPAddress.HostToNetworkOrder((int)SentCount)), 0, byPacketHeader, 0x0C, 4);
		Array.Copy(BitConverter.GetBytes(System.Net.IPAddress.HostToNetworkOrder((int)ReceivedCount)), 0, byPacketHeader, 0x10, 4);

		Array.Copy(byPacketHeader, byPacket, 28);

		if (bData != null) SentCount += (uint)bData.Length;
		return (iPhone.SendToiPhone(byPacket) - 28);
	}

	// Receives packet from iPhone, strips header and passes along
	// the actual data.
	protected byte[] Receive()
	{
		if (iPhone == null || !iPhone.Usable) throw new Exception("No device ready in USBMUXConnection constructor.");

		byte[] bData;

		// If packets were received by another connection by accident, they will be buffered
		// here and calls to USBMUXReceive should exhaust the buffer before continuing to poll
		// the iPhone.
		if (BufferedPacketsWaiting.Count > 0)
		{
			// The buffered packets already have their headers stripped.
			bData = BufferedPacketsWaiting.Dequeue();
			ReceivedCount += (uint)bData.Length;
			return bData;
		}

		byte[] byPacket = iPhone.ReceiveFromiPhone();
		if (byPacket == null || byPacket.Length < 28)
			throw new Exception("USBMUXReceive got malformed data.");

		// Check if we have the right ports.
		ushort nPacketSourcePort = (ushort)(System.Net.IPAddress.NetworkToHostOrder((int)BitConverter.ToUInt16(byPacket, 0x0A)) >> 16);
		ushort nPacketDestPort = (ushort)(System.Net.IPAddress.NetworkToHostOrder((int)BitConverter.ToUInt16(byPacket, 0x08)) >> 16);
		if (nPacketSourcePort != SourcePort || nPacketDestPort != DestPort)
		{
			// Wrong port. Redirect traffic and then try again.
			iPhone.RedirectMUXPacket(byPacket);
			return Receive();
		}

		ReceivedCount += (uint)(byPacket.Length - 28);
		bData = new byte[byPacket.Length - 28];
		Array.Copy(byPacket, 28, bData, 0, byPacket.Length - 28);

		return bData;
	}

	// Called by iPhoneWrapper::RedirectMUXPacket. Strip MUX header and add to queue.
	public void BufferPacket(byte[] byPacket)
	{
		if (byPacket.Length < 28) return;
		byte[] bData = new byte[byPacket.Length - 28];
		Array.Copy(byPacket, 28, bData, 0, byPacket.Length - 28);
		BufferedPacketsWaiting.Enqueue(bData);
	}
}

class AFCConnection : USBMUXConnection
{
	enum AFCPacketType : long
	{
		Status = 0x00000001L,
		Data = 0x00000002L,
		ListDirectory = 0x00000003L,
		ReadFile = 0x00000004L,
		WriteFile = 0x00000005L,
		WritePart = 0x00000006L,
		TruncateFile = 0x00000007L,
		RemovePath = 0x00000008L,
		MakeDirectory = 0x00000009L,
		GetFileInfo = 0x0000000AL,
		GetDeviceInfo = 0x0000000BL,
		WriteFileAtomic = 0x0000000CL,	// (tmp file+rename)
		FileRefOpen = 0x0000000DL,
		FileRefOpenResult = 0x0000000EL,
		FileRefRead = 0x0000000FL,
		FileRefWrite = 0x00000010L,
		FileRefSeek = 0x00000011L,
		FileRefTell = 0x00000012L,
		FileRefTellResult = 0x00000013L,
		FileRefClose = 0x00000014L,
		FileRefSetFileSize = 0x00000015L,
		GetConnectionInfo = 0x00000016L,
		SetConnectionOptions = 0x00000017L,
		RenamePath = 0x00000018L,
		SetFSBlockSize = 0x00000019L,
		SetSocketBlockSize = 0x0000001AL,
		FileRefLock = 0x0000001BL,
		MakeLink = 0x0000001CL,
		SetFileTime = 0x0000001EL
	}
	enum AFCErrorCode : long
	{
		Success = 0x00000000L,
		UnknownError = 0x00000001L,
		HandleNotFound = 0x00000007L,
		FileNotFound = 0x00000008L,
		ObjectIsDirectory = 0x00000009L,
		OpWouldBlock = 0x00000013L
	}
	class AFCPacketData
	{
		public AFCPacketType Type;
		public byte[] bData;
	}

	// AFC packets received from the iPhone will typically be broken up into what I call
	// "packet streams". The first packet in a stream will contain an AFC header which
	// contains the length of the entire packet stream to be expected.

	// AFC header is 40 bytes:
	//		8 bytes: const byte string AFCConst (reads "AAPL6AFC" upon byteswap).
	//		8 bytes: length of entire packet stream (includes header length (constant 0x28)).
	//		8 bytes: length of present packet's AFC data, including the header's length.
	//		8 bytes: packet counter. incremented by one each time a packet stream is sent.
	//		8 bytes: command (make dir, rename, etc.).

	static System.Threading.Mutex AFCMutex = new System.Threading.Mutex(false);
	static byte[] AFCConst = new byte[] { 0x43, 0x46, 0x41, 0x36, 0x4C, 0x50, 0x41, 0x41 };
	long nPacketCounter;

	public AFCConnection(iPhoneWrapper IPW, ushort SPort, ushort DPort)
		: base(IPW, SPort, DPort)
	{
		nPacketCounter = 0;
	}

	// Wrapper that null-terminates strings being sent as AFC packets.
	private int AFCSend(string sData, AFCPacketType Type)
	{
		if (sData == null) throw new Exception("No data passed to AFCSend.");
		sData += '\x0';
		return AFCSend(System.Text.Encoding.UTF8.GetBytes(sData), Type);
	}

	// Sends an AFC packet to iPhone.
	private int AFCSend(byte[] bData, AFCPacketType Type)
	{
		if (iPhone == null || !iPhone.Usable) throw new Exception("No device ready in AFCSend.");
		if (bData == null) throw new Exception("No data passed to AFCSend.");

		long nPacketLength = bData.LongLength + 40;
		byte[] bAugmentedData = new byte[nPacketLength];
		Array.Copy(AFCConst, bAugmentedData, 8);
		Array.Copy(BitConverter.GetBytes(nPacketLength), 0, bAugmentedData, 8, 8);
		// Hack because of AFC inconsistency.
		if (Type == AFCPacketType.FileRefWrite)
			Array.Copy(BitConverter.GetBytes((long)0x30), 0, bAugmentedData, 16, 8);
		else
			Array.Copy(BitConverter.GetBytes(nPacketLength), 0, bAugmentedData, 16, 8);
		Array.Copy(BitConverter.GetBytes(nPacketCounter), 0, bAugmentedData, 24, 8);
		Array.Copy(BitConverter.GetBytes((long)Type), 0, bAugmentedData, 32, 8);
		Array.Copy(bData, 0, bAugmentedData, 40, bData.Length);

		nPacketCounter++;
		return Send(bAugmentedData);
	}

	// Listens to an AFC packet stream and concatenates the contents.
	private AFCPacketData AFCReceive()
	{
		if (iPhone == null || !iPhone.Usable) throw new Exception("No device ready in AFCReceive.");

		long nPacketStreamLength, nBytesReceived;
		byte[] byReceivedData;

		// Get first packet of packet stream and extract total packet stream length.
		byte[] byPacket = Receive();
		if (byPacket == null || byPacket.Length < 40) throw new Exception("Didn't get well-formed packet in AFCReceive.");
		nPacketStreamLength = BitConverter.ToInt64(byPacket, 8) - 40;

		AFCPacketData ReceivedPacket = new AFCPacketData();
		ReceivedPacket.Type = (AFCPacketType)BitConverter.ToInt64(byPacket, 32);

		nBytesReceived = 0;
		byReceivedData = new byte[nPacketStreamLength];
		if (byPacket.Length > 40)
		{
			Array.Copy(byPacket, 40, byReceivedData, 0, byPacket.Length - 40);
			nBytesReceived += byPacket.Length - 40;
		}

		while (nBytesReceived < nPacketStreamLength)
		{
			byPacket = Receive();
			if (byPacket == null) break;
			Array.Copy(byPacket, 0, byReceivedData, nBytesReceived, byPacket.Length);
			nBytesReceived += byPacket.Length;
		}

		ReceivedPacket.bData = byReceivedData;
		return ReceivedPacket;
	}

	// Retrieves file size and type (i.e. file or directory).
	// Throws FileNotFoundException, Exception.
	public string GetFileInfo(string sPath)
	{
		AFCMutex.WaitOne();
		AFCSend(sPath, AFCPacketType.GetFileInfo);
		AFCPacketData Packet = AFCReceive();
		AFCMutex.ReleaseMutex();

		if (Packet.Type == AFCPacketType.Data)
			return System.Text.Encoding.UTF8.GetString(Packet.bData);

		// Otherwise, something went wrong.
		if (Packet.Type == AFCPacketType.Status && Packet.bData != null && Packet.bData.Length == 8)
		{
			long nErrorCode = BitConverter.ToInt64(Packet.bData, 0);
			switch (nErrorCode)
			{
				case (long)AFCErrorCode.FileNotFound:
					throw new FileNotFoundException();

				default:
					throw new Exception("AFCConnection::GetFileInfo got error code " + nErrorCode + ".");
			}
		}

		throw new Exception("AFCConnection::GetFileInfo should never reach here.");
	}

	// Makes a directory.
	// Throws Exception.
	public void MakeDirectory(string sPath)
	{
		AFCMutex.WaitOne();
		AFCSend(sPath, AFCPacketType.MakeDirectory);
		AFCPacketData Packet = AFCReceive();
		AFCMutex.ReleaseMutex();

		if (Packet.Type != AFCPacketType.Status || Packet.bData.Length != 8
				|| BitConverter.ToInt64(Packet.bData, 0) != (long)AFCErrorCode.Success)
			throw new Exception();
	}

	// Removes a file or directory.
	// Throws IOException, Exception.
	public void RemovePath(string sPath)
	{
		AFCMutex.WaitOne();
		AFCSend(sPath, AFCPacketType.RemovePath);
		AFCPacketData Packet = AFCReceive();
		AFCMutex.ReleaseMutex();

		if (Packet.Type != AFCPacketType.Status || Packet.bData.Length != 8)
			throw new Exception();

		long nErrorCode = BitConverter.ToInt64(Packet.bData, 0);
		switch (nErrorCode)
		{
			case (long)AFCErrorCode.Success:
				return;

			case (long)AFCErrorCode.UnknownError:
				// Means directory is not empty, apparently.
				throw new IOException("Path not empty.");

			default:
				throw new Exception();
		}
	}

	// Renames (moves) a file or directory.
	// Throws Exception.
	public void RenamePath(string sPath, string sNewPath)
	{
		byte[] bPath = System.Text.Encoding.UTF8.GetBytes(sPath);
		byte[] bNewPath = System.Text.Encoding.UTF8.GetBytes(sNewPath);
		byte[] byPacket = new byte[bPath.Length + 1 + bNewPath.Length + 1];
		Array.Copy(bPath, 0, byPacket, 0, bPath.Length);
		byPacket[bPath.Length] = 0;
		Array.Copy(bNewPath, 0, byPacket, bPath.Length + 1, bNewPath.Length);
		byPacket[byPacket.Length - 1] = 0;

		AFCMutex.WaitOne();
		AFCSend(byPacket, AFCPacketType.RenamePath);
		AFCPacketData Packet = AFCReceive();
		AFCMutex.ReleaseMutex();

		if (Packet.Type != AFCPacketType.Status || Packet.bData.Length != 8
				|| BitConverter.ToInt64(Packet.bData, 0) != (long)AFCErrorCode.Success)
			throw new Exception();
	}

	// Retrieves a directory listing.
	// Throws Exception.
	public string[] ListDirectory(string sPath)
	{
		AFCMutex.WaitOne();
		AFCSend(sPath, AFCPacketType.ListDirectory);
		AFCPacketData Packet = AFCReceive();
		AFCMutex.ReleaseMutex();

		if (Packet.Type == AFCPacketType.Data)
			return System.Text.Encoding.UTF8.GetString(Packet.bData).Split(new char[] { '\x0' });

		// Otherwise, something went wrong.
		if (Packet.Type == AFCPacketType.Status && Packet.bData != null && Packet.bData.Length == 8)
		{
			long nErrorCode = BitConverter.ToInt64(Packet.bData, 0);
			switch (nErrorCode)
			{
				default:
					throw new Exception("AFCConnection::ListDirectory got error code " + nErrorCode + ".");
			}
		}

		throw new Exception("AFCConnection::ListDirectory should never reach here.");
	}

	// Retrieves a couple of things, notably disk space.
	// Throws Exception.
	public string GetDeviceInfo()
	{
		AFCMutex.WaitOne();
		AFCSend(String.Empty, AFCPacketType.GetDeviceInfo);
		AFCPacketData Packet = AFCReceive();
		AFCMutex.ReleaseMutex();

		if (Packet.Type == AFCPacketType.Data)
			return System.Text.Encoding.UTF8.GetString(Packet.bData);

		// Otherwise, something went wrong.
		if (Packet.Type == AFCPacketType.Status && Packet.bData != null && Packet.bData.Length == 8)
		{
			long nErrorCode = BitConverter.ToInt64(Packet.bData, 0);
			switch (nErrorCode)
			{
				default:
					throw new Exception("AFCConnection::GetDeviceInfo got error code " + nErrorCode + ".");
			}
		}

		throw new Exception("AFCConnection::GetDeviceInfo should never reach here.");
	}

	// Accesses a file on the iPhone and returns a handle to be used
	// in further requests, such as ReadFile, WriteFile, etc.
	// Throws FileNotFoundException, Exception.
	public long OpenFile(string sPath, AFCFileMode FM)
	{
		byte[] bPath = System.Text.Encoding.UTF8.GetBytes(sPath);
		byte[] byPacket = new byte[bPath.Length + 8 + 1];
		Array.Copy(BitConverter.GetBytes((long)FM), byPacket, 8);
		Array.Copy(bPath, 0, byPacket, 8, bPath.Length);
		byPacket[byPacket.Length - 1] = 0;

		AFCMutex.WaitOne();
		AFCSend(byPacket, AFCPacketType.FileRefOpen);
		AFCPacketData Packet = AFCReceive();
		AFCMutex.ReleaseMutex();

		if (Packet.Type == AFCPacketType.FileRefOpenResult && Packet.bData.Length == 8)
			return BitConverter.ToInt64(Packet.bData, 0);

		// Otherwise, something went wrong.
		if (Packet.Type == AFCPacketType.Status && Packet.bData != null && Packet.bData.Length == 8)
		{
			long nErrorCode = BitConverter.ToInt64(Packet.bData, 0);
			switch (nErrorCode)
			{
				case (long)AFCErrorCode.FileNotFound:
					throw new FileNotFoundException();

				default:
					throw new Exception("AFCConnection::OpenFile got error code " + nErrorCode + ".");
			}
		}

		throw new Exception("AFCConnection::OpenFile should never reach here.");
	}

	// Closes a file
	// Throws Exception.
	public void CloseFile(long nFileHandle)
	{
		AFCMutex.WaitOne();
		AFCSend(BitConverter.GetBytes(nFileHandle), AFCPacketType.FileRefClose);
		AFCPacketData Packet = AFCReceive();
		AFCMutex.ReleaseMutex();

		if (Packet.Type != AFCPacketType.Status || Packet.bData.Length != 8
				|| BitConverter.ToInt64(Packet.bData, 0) != (long)AFCErrorCode.Success)
			throw new Exception();
	}

	// Seeks to offset within file contents.
	// Throws Exception.
	public void SeekFile(long nFileHandle, long nOffset)
	{
		// SEEK_SET = 0, SEEK_CUR = 1, SEEK_END = 2.
		byte[] byPacket = new byte[8 + 8 + 8];
		Array.Copy(BitConverter.GetBytes(nFileHandle), byPacket, 8);
		Array.Copy(BitConverter.GetBytes((long)0), 0, byPacket, 8, 8); // Seek from beginning.
		Array.Copy(BitConverter.GetBytes(nOffset), 0, byPacket, 16, 8);

		AFCMutex.WaitOne();
		AFCSend(byPacket, AFCPacketType.FileRefSeek);
		AFCPacketData Packet = AFCReceive();
		AFCMutex.ReleaseMutex();

		if (Packet.Type != AFCPacketType.Status || Packet.bData.Length != 8
				|| BitConverter.ToInt64(Packet.bData, 0) != (long)AFCErrorCode.Success)
			throw new Exception();
	}

	// Reads nBytesToRead bytes from the contents of a file.
	// Throws Exception.
	public byte[] ReadFile(long nFileHandle, long nBytesToRead)
	{
		// Break up big requests into 64 KB chunks to not run afoul of
		// any packet size restrictions.
		const long MaxReadSize = 64 * 1024;

		long nReceivedBytes = 0;
		byte[] byFileData = new byte[nBytesToRead];

		while (nReceivedBytes < nBytesToRead)
		{
			byte[] byPacket = new byte[8 + 8];
			Array.Copy(BitConverter.GetBytes(nFileHandle), byPacket, 8);
			Array.Copy(BitConverter.GetBytes((long)
				((nBytesToRead - nReceivedBytes) < MaxReadSize ? (nBytesToRead - nReceivedBytes) : MaxReadSize)),
				0, byPacket, 8, 8);

			AFCMutex.WaitOne();
			AFCSend(byPacket, AFCPacketType.FileRefRead);
			AFCPacketData Packet = AFCReceive();
			AFCMutex.ReleaseMutex();

			if (Packet.Type == AFCPacketType.Data && Packet.bData != null)
			{
				Array.Copy(Packet.bData, 0, byFileData, nReceivedBytes, Packet.bData.LongLength);
				nReceivedBytes += Packet.bData.LongLength;

				if (Packet.bData.Length == 0) break;
			}
			else if (Packet.Type == AFCPacketType.Status && Packet.bData != null && Packet.bData.Length == 8)
			{
				long nErrorCode = BitConverter.ToInt64(Packet.bData, 0);
				switch (nErrorCode)
				{
					default:
						throw new Exception("AFCConnection::ReadFile got error code " + nErrorCode + ".");
				}
			}
			else
				throw new Exception("AFCConnection::ReadFile suffered an unknown fault.");

			// It might be valid that the file finishes before nReceivedBytes are received.
			// e.g. Notepad reads 512 bytes at a time, regardless of file size.
		}

		Array.Resize<byte>(ref byFileData, (int)nReceivedBytes);
		return byFileData;
	}

	// Writes bData to a file.
	// Throws Exception.
	public uint WriteFile(long nFileHandle, byte[] bData)
	{
		// Break up big requests into 32 KB chunks to not run afoul of
		// any packet size restrictions.
		const long MaxWriteSize = 32 * 1024;

		long nWrittenBytes = 0;

		AFCMutex.WaitOne();
		while (nWrittenBytes < bData.LongLength)
		{
			long nPacketDataLength = ((bData.LongLength - nWrittenBytes) > MaxWriteSize ? MaxWriteSize : (bData.LongLength - nWrittenBytes));
			byte[] byPacket = new byte[8 + nPacketDataLength];
			Array.Copy(BitConverter.GetBytes(nFileHandle), byPacket, 8);
			Array.Copy(bData, nWrittenBytes, byPacket, 8, nPacketDataLength);
			AFCSend(byPacket, AFCPacketType.FileRefWrite);
			AFCPacketData Packet = AFCReceive();

			// TODO: throw appropriate exceptions at this stage.
			if (Packet.Type != AFCPacketType.Status || Packet.bData.Length != 8
				|| BitConverter.ToInt64(Packet.bData, 0) != (long)AFCErrorCode.Success)
				break;

			nWrittenBytes += nPacketDataLength;
		}
		AFCMutex.ReleaseMutex();

		if (nWrittenBytes == bData.LongLength)
			return (uint)bData.Length;

		// Otherwise, something went wrong.
		throw new Exception("Wrote " + nWrittenBytes + " bytes. Expected to write " + bData.LongLength + ".");
	}

	// Changes the length of a file.
	// Throws Exception.
	public void SetFileLength(long nFileHandle, long nNewSize)
	{
		byte[] byPacket = new byte[8 + 8];
		Array.Copy(BitConverter.GetBytes(nFileHandle), byPacket, 8);
		Array.Copy(BitConverter.GetBytes(nNewSize), 0, byPacket, 8, 8);

		AFCMutex.WaitOne();
		AFCSend(byPacket, AFCPacketType.FileRefSetFileSize);
		AFCPacketData Packet = AFCReceive();
		AFCMutex.ReleaseMutex();

		if (Packet.Type != AFCPacketType.Status || Packet.bData.Length != 8
				|| BitConverter.ToInt64(Packet.bData, 0) != (long)AFCErrorCode.Success)
			throw new Exception();
	}

	// Locks a file.
	// Throws Exception, InvalidOperationException.
	public void LockFile(long nFileHandle, AFCLockOperation LockOperation)
	{
		byte[] byPacket = new byte[8 + 8];
		Array.Copy(BitConverter.GetBytes(nFileHandle), byPacket, 8);
		Array.Copy(BitConverter.GetBytes((long)LockOperation), 0, byPacket, 8, 8);

		AFCMutex.WaitOne();
		AFCSend(byPacket, AFCPacketType.FileRefLock);
		AFCPacketData Packet = AFCReceive();
		AFCMutex.ReleaseMutex();

		if (Packet.Type == AFCPacketType.Status && Packet.bData != null && Packet.bData.Length == 8)
		{
			long nErrorCode = BitConverter.ToInt64(Packet.bData, 0);
			switch (nErrorCode)
			{
				case (long)AFCErrorCode.Success:
					return;

				case (long)AFCErrorCode.OpWouldBlock:
					throw new InvalidOperationException();

				default:
					throw new Exception("AFCConnection::LockFile got error code " + nErrorCode + ".");
			}
		}
		else
			throw new Exception("AFCConnection::LockFile suffered an unknown fault.");
	}
}

abstract class PListConnection : USBMUXConnection
{
	// Omits 3-byte "byte-order marker" that would preface the stream by default.
	protected static System.Text.Encoding UTF8SansBOM = new System.Text.UTF8Encoding(false);
	protected static XmlWriterSettings XWS;
	protected const string sApplePubID = "-//Apple Computer//DTD PLIST 1.0//EN";
	protected const string sAppleSysID = "http://www.apple.com/DTDs/PropertyList-1.0.dtd";
	protected System.Net.Security.SslStream SSLConnection;
	protected bool UsingSSL { get { return (SSLConnection != null); } }

	public PListConnection(iPhoneWrapper IPW, ushort SPort, ushort DPort)
		: base(IPW, SPort, DPort)
	{
		if (XWS == null)
		{
			XWS = new XmlWriterSettings();
			XWS.NewLineChars = "\n";
			XWS.Encoding = UTF8SansBOM;
			XWS.Indent = true;
			XWS.IndentChars = "\t";
		}
	}

	// Sends a plist packet to iPhone, in either SSL or non-SSL mode.
	// Header is simply a 4-byte length prefacing the payload itself.
	protected int PListSend(byte[] bData)
	{
		if (iPhone == null || !iPhone.Usable) throw new Exception("No device ready in PListSend.");
		if (bData == null) throw new Exception("No data passed to PListSend.");

		byte[] bAugmentedData = new byte[4 + bData.Length];
		Array.Copy(BitConverter.GetBytes(System.Net.IPAddress.HostToNetworkOrder((int)bData.Length)), bAugmentedData, 4);
		Array.Copy(bData, 0, bAugmentedData, 4, bData.Length);

		// If SSL encryption is on, pass buffer along to SSLConnection.
		if (UsingSSL)
		{
			SSLConnection.Write(bAugmentedData);
			// FIXME: probably of no consequence, but this should return the length of
			// the encrypted data. No easy way to do it?
			return bAugmentedData.Length;
		}
		else
			return Send(bAugmentedData);
	}

	// Reads a plist packet from the iPhone, in either SSL or non-SSL mode.
	protected byte[] PListReceive()
	{
		if (iPhone == null || !iPhone.Usable) throw new Exception("No device ready in PListReceive.");

		// Incoming data will come in two packets.
		// First packet has 4 byte payload, saying how many bytes the real data will be.
		// Second packet has the actual data.
		if (UsingSSL)
		{
			byte[] byBuffer = new byte[128 * 1024];
			SSLConnection.Read(byBuffer, 0, 128 * 1024);
			int nPacketLength = System.Net.IPAddress.NetworkToHostOrder(BitConverter.ToInt32(byBuffer, 0));
			byBuffer = new byte[nPacketLength];

			int nRead = 0, nReadTotal = 0;
			while (nReadTotal < nPacketLength)
			{
				nRead = SSLConnection.Read(byBuffer, nReadTotal, nPacketLength - nReadTotal);
				if (nRead == 0) break;
				nReadTotal += nRead;
			}

			Array.Resize(ref byBuffer, nReadTotal);
			return byBuffer;
		}
		else
		{
			Receive();
			return Receive();
		}
	}

	protected static bool CheckXMLForSuccess(byte[] bXMLData)
	{
		if (bXMLData == null || bXMLData.Length == 0) return false;

		MemoryStream MS = new MemoryStream(bXMLData);
		XmlDocument XD = new XmlDocument();
		XD.XmlResolver = null; // Don't fetch DTD from web. Speeds things up tremendously.
		XD.Load(MS);
		MS.Close();
		if (XD["plist"]["dict"].SelectSingleNode("key[text()='Result']") == null
			|| XD["plist"]["dict"].SelectSingleNode("key[text()='Result']").NextSibling.InnerText != "Success")
			return false;

		return true;
	}
}

class NotificationProxyConnection : PListConnection
{
	public const string SyncWillStart = "com.apple.itunes-mobdev.syncWillStart";
	public const string SyncLockRequest = "com.apple.itunes-mobdev.syncLockRequest";
	public const string SyncDidStart = "com.apple.itunes-mobdev.syncDidStart";
	public const string SyncFailedToStart = "com.apple.itunes-mobdev.syncFailedToStart";
	public const string SyncDidFinish = "com.apple.itunes-mobdev.syncDidFinish";
	public const string PostProcessingWillBegin = "com.apple.itdbprep.notification.willBegin";
	public const string PostProcessingDidEnd = "com.apple.itdbprep.notification.didEnd";

	static System.Threading.Mutex NPMutex = new System.Threading.Mutex(false);

	public NotificationProxyConnection(iPhoneWrapper IPW, ushort SPort, ushort DPort)
		: base(IPW, SPort, DPort)
	{

	}

	public override void CloseConnection()
	{
		MemoryStream MS;
		XmlWriter XTW;
		byte[] bXMLData;

		MS = new MemoryStream();
		XTW = XmlWriter.Create(MS, XWS);
		XTW.WriteStartDocument();
		XTW.WriteDocType("plist", sApplePubID, sAppleSysID, null);
		XTW.WriteStartElement("plist");
		XTW.WriteAttributeString("version", "1.0");
		XTW.WriteStartElement("dict");
		
		XTW.WriteElementString("key", "Command");
		XTW.WriteElementString("string", "Shutdown");
		
		XTW.WriteEndElement(); // dict
		XTW.WriteEndElement(); // plist
		XTW.WriteEndDocument();
		XTW.Flush();

		bXMLData = MS.GetBuffer();
		XTW.Close(); // Closes MS, too.

		PListSend(bXMLData);
		Receive();
	}

	public void PostNotification(string sNotification)
	{
		if (iPhone == null || !iPhone.Usable) throw new Exception("No device ready in PostNotification.");

		MemoryStream MS = new MemoryStream();
		XmlWriter XTW = XmlWriter.Create(MS, XWS);
		XTW.WriteStartDocument();
		XTW.WriteDocType("plist", sApplePubID, sAppleSysID, null);
		XTW.WriteStartElement("plist");
		XTW.WriteAttributeString("version", "1.0");
		XTW.WriteStartElement("dict");

		XTW.WriteElementString("key", "Command");
		XTW.WriteElementString("string", "PostNotification");
		XTW.WriteElementString("key", "Name");
		XTW.WriteElementString("string", sNotification);

		XTW.WriteEndElement(); // dict
		XTW.WriteEndElement(); // plist
		XTW.WriteEndDocument();
		XTW.Flush();

		byte[] bXMLData = MS.GetBuffer();
		XTW.Close(); // Closes MS, too.

		NPMutex.WaitOne();
		PListSend(bXMLData);
		NPMutex.ReleaseMutex();
	}
}

class LockdownConnection : PListConnection
{
	enum PairAction { Pair = 0, ValidatePair = 1, Unpair = 2 };

	SSLHelperStream SSLInOutStream;
	string sSessionID;
	Org.BouncyCastle.Crypto.Parameters.RsaKeyParameters DevicePublicKey;
	Org.BouncyCastle.X509.X509Certificate DeviceCertificate;

	public LockdownConnection(iPhoneWrapper IPW) : base(IPW, 0x0A00, 0xF27E)
	{
		MemoryStream MS = new MemoryStream();
		XmlWriter XTW = XmlWriter.Create(MS, XWS);
		XTW.WriteStartDocument();
		XTW.WriteDocType("plist", sApplePubID, sAppleSysID, null);
		XTW.WriteStartElement("plist");
		XTW.WriteAttributeString("version", "1.0");
		XTW.WriteStartElement("dict");
		XTW.WriteElementString("key", "Request");
		XTW.WriteElementString("string", "QueryType");
		XTW.WriteEndElement(); // dict
		XTW.WriteEndElement(); // plist
		XTW.WriteEndDocument();
		XTW.Flush();

		byte[] bXMLData = MS.GetBuffer();
		XTW.Close(); // Closes MS, too.

		PListSend(bXMLData);
		bXMLData = PListReceive();

		if (!CheckXMLForSuccess(bXMLData))
			throw new Exception("Lockdown hello wasn't successful.");

		#region Get public key
		// Public key is encrypted in base 64.
		string sPublicKey = GetValueFromDevice(null, "DevicePublicKey");

		// Decode sPublicKey from base 64, the result of which looks like
		// "
		// -----BEGIN RSA PUBLIC KEY-----
		// MIGJAoGBAIBNlqucaJt9Q9uX/uYgd5TRYbK4Y3tjMrrkIWThpVL/ry3rTovr9J3b
		// eGaHLUHLU/0ykXB+k7N+li7dOWhOdeAid/k5c5q4UlrOl1+eScsKeR1xUqQD2WMqGL0
		// gsOSstN+38SDOqVxcpP/geTMZsecInrgxv0asbStXdyXdy2DvJaHl2/AgMBAAE=
		// -----END RSA PUBLIC KEY-----
		// "
		byte[] bDecoded = Convert.FromBase64String(sPublicKey);

		// Read the RSA public key into a BouncyCastle structure, to be used in
		// making an X.509 device certificate.
		MS = new MemoryStream(bDecoded);
		TextReader TR = new StreamReader(MS);
		Org.BouncyCastle.OpenSsl.PemReader PR = new Org.BouncyCastle.OpenSsl.PemReader(TR);
		DevicePublicKey = (Org.BouncyCastle.Crypto.Parameters.RsaKeyParameters)PR.ReadObject();
		TR.Close();
		MS.Close();
		#endregion
	}
	public override void CloseConnection()
	{
		MemoryStream MS;
		XmlWriter XTW;
		byte[] bXMLData;

		if (UsingSSL)
		{
			#region Send StopSession plist
			MS = new MemoryStream();
			XTW = XmlWriter.Create(MS, XWS);
			XTW.WriteStartDocument();
			XTW.WriteDocType("plist", sApplePubID, sAppleSysID, null);
			XTW.WriteStartElement("plist");
			XTW.WriteAttributeString("version", "1.0");
			XTW.WriteStartElement("dict");

			XTW.WriteElementString("key", "Request");
			XTW.WriteElementString("string", "StopSession");
			XTW.WriteElementString("key", "SessionID");
			XTW.WriteElementString("string", sSessionID);

			XTW.WriteEndElement(); // dict
			XTW.WriteEndElement(); // plist
			XTW.WriteEndDocument();
			XTW.Flush();

			bXMLData = MS.GetBuffer();
			XTW.Close(); // Closes MS, too.

			PListSend(bXMLData);
			try { PListReceive(); }
			catch { }
			#endregion

			SSLConnection.Close();
			SSLConnection = null;
			Global.Log("Stopped SSL session with lockdownd.\n");
		}

		#region Send goodbye plist
		MS = new MemoryStream();
		XTW = XmlWriter.Create(MS, XWS);
		XTW.WriteStartDocument();
		XTW.WriteDocType("plist", sApplePubID, sAppleSysID, null);
		XTW.WriteStartElement("plist");
		XTW.WriteAttributeString("version", "1.0");
		XTW.WriteStartElement("dict");

		XTW.WriteElementString("key", "Request");
		XTW.WriteElementString("string", "Goodbye");

		XTW.WriteEndElement(); // dict
		XTW.WriteEndElement(); // plist
		XTW.WriteEndDocument();
		XTW.Flush();

		bXMLData = MS.GetBuffer();
		XTW.Close(); // Closes MS, too.

		PListSend(bXMLData);
		Receive();
		#endregion
	}

	// Send either ValidatePair or Pair (depending on Action)
	// request to iPhone and return true upon success or false otherwise.
	private bool Pair(PairAction Action)
	{
		#region Preparation of certificates
		X509V3CertificateGenerator DeviceCG = new X509V3CertificateGenerator();
		DeviceCG.SetPublicKey(DevicePublicKey);
		DeviceCG.SetSerialNumber(Org.BouncyCastle.Math.BigInteger.Zero);
		DeviceCG.SetNotBefore(iPhone.RootCertificate.NotBefore);
		DeviceCG.SetNotAfter(iPhone.RootCertificate.NotAfter);
		//DeviceCG.SetIssuerDN(new Org.BouncyCastle.Asn1.X509.X509Name(new ArrayList(), new ArrayList()));
		//DeviceCG.SetSubjectDN(new Org.BouncyCastle.Asn1.X509.X509Name(new ArrayList(), new ArrayList()));
		DeviceCG.SetSignatureAlgorithm("SHA1WithRSAEncryption");
		DeviceCG.AddExtension(Org.BouncyCastle.Asn1.X509.X509Extensions.BasicConstraints, true, new Org.BouncyCastle.Asn1.X509.BasicConstraints(false));
		// DEBUG removing these x509 extensions.
		//Org.BouncyCastle.Asn1.X509.SubjectKeyIdentifier DeviceSKI = new Org.BouncyCastle.X509.Extension.SubjectKeyIdentifierStructure(DevicePublicKey);
		//DeviceCG.AddExtension(Org.BouncyCastle.Asn1.X509.X509Extensions.SubjectKeyIdentifier, false, DeviceSKI);
		//DeviceCG.AddExtension(Org.BouncyCastle.Asn1.X509.X509Extensions.KeyUsage, true,
		//			new Org.BouncyCastle.Asn1.X509.KeyUsage(Org.BouncyCastle.Asn1.X509.KeyUsage.KeyEncipherment | Org.BouncyCastle.Asn1.X509.KeyUsage.DigitalSignature));
		DeviceCertificate = DeviceCG.Generate(iPhone.RootKey.Private);

		// The \n at the end of these certificates is crucial; hung me up for a while.
		string sDeviceCertificate = "-----BEGIN CERTIFICATE-----\n"
									+ Convert.ToBase64String(DeviceCertificate.GetEncoded())
									+ "\n-----END CERTIFICATE-----\n";
		byte[] bDeviceCertificate = System.Text.Encoding.UTF8.GetBytes(sDeviceCertificate);
		string sHostCertificate = "-----BEGIN CERTIFICATE-----\n"
									+ Convert.ToBase64String(iPhone.HostCertificate.GetEncoded())
									+ "\n-----END CERTIFICATE-----\n";
		byte[] bHostCertificate = System.Text.Encoding.UTF8.GetBytes(sHostCertificate);
		string sRootCertificate = "-----BEGIN CERTIFICATE-----\n"
									+ Convert.ToBase64String(iPhone.RootCertificate.GetEncoded())
									+ "\n-----END CERTIFICATE-----\n";
		byte[] bRootCertificate = System.Text.Encoding.UTF8.GetBytes(sRootCertificate);
		#endregion

		MemoryStream MS = new MemoryStream();
		XmlWriter XTW = XmlWriter.Create(MS, XWS);
		XTW.WriteStartDocument();
		XTW.WriteDocType("plist", sApplePubID, sAppleSysID, null);
		XTW.WriteStartElement("plist");
		XTW.WriteAttributeString("version", "1.0");
		XTW.WriteStartElement("dict");

		XTW.WriteElementString("key", "PairRecord");
		XTW.WriteStartElement("dict");

		XTW.WriteElementString("key", "DeviceCertificate");
		XTW.WriteStartElement("data");
		XTW.WriteBase64(bDeviceCertificate, 0, bDeviceCertificate.Length);
		XTW.WriteEndElement(); // DeviceCertificate data

		XTW.WriteElementString("key", "HostCertificate");
		XTW.WriteStartElement("data");
		XTW.WriteBase64(bHostCertificate, 0, bHostCertificate.Length);
		XTW.WriteEndElement(); // HostCertificate data

		XTW.WriteElementString("key", "HostID");
		XTW.WriteElementString("string", iPhone.sHostID);
		XTW.WriteElementString("key", "RootCertificate");
		XTW.WriteStartElement("data");
		XTW.WriteBase64(bRootCertificate, 0, bRootCertificate.Length);
		XTW.WriteEndElement(); // RootCertificate data

		XTW.WriteEndElement(); // inner dict

		XTW.WriteElementString("key", "Request");
		switch (Action)
		{
			case PairAction.Pair:
				XTW.WriteElementString("string", "Pair");
				break;

			case PairAction.ValidatePair:
				XTW.WriteElementString("string", "ValidatePair");
				break;

			case PairAction.Unpair:
				XTW.WriteElementString("string", "Unpair");
				break;
		}

		XTW.WriteEndElement(); // outer dict
		XTW.WriteEndElement(); // plist
		XTW.WriteEndDocument();
		XTW.Flush();

		byte[] bXMLData = MS.GetBuffer();
		XTW.Close(); // Closes MS, too.

		PListSend(bXMLData);
		bXMLData = PListReceive();

		if (!CheckXMLForSuccess(bXMLData))
			return false;

		// Have to validate after pairing for "trusted host status", apparently.
		if (Action == PairAction.Pair)
			return Pair(PairAction.ValidatePair);

		return true;
	}

	public void Authenticate()
	{
		if (iPhone.sHostID == null) iPhone.sHostID = iPhoneWrapper.GenerateHostID();
		Global.Log("Authenticating with device... ");

		if (Pair(PairAction.ValidatePair))
		{
			Global.Log("success!\n", true);

			//Global.Log("Unpairing...\n"); Pair(PairAction.Unpair); throw new Exception("abort after unpairing");
			StartSession();
		}
		else
		{
			// Try to pair and, if successful, commit the stuff to registry.
			if (Pair(PairAction.Pair))
			{
				Global.Log("success! (New pairing)\n", true);
				iPhone.CommitCryptoStuffToRegistry();
				StartSession();
			}
			else
			{
				Global.Log("failed!\n", true);
				throw new Exception("Failed to pair device with lockdownd.\n");
			}
		}
	}
	private void StartSession()
	{
		Global.Log("Starting SSL session with lockdownd... ");

		MemoryStream MS = new MemoryStream();
		XmlWriter XTW = XmlWriter.Create(MS, XWS);
		XTW.WriteStartDocument();
		XTW.WriteDocType("plist", sApplePubID, sAppleSysID, null);
		XTW.WriteStartElement("plist");
		XTW.WriteAttributeString("version", "1.0");
		XTW.WriteStartElement("dict");

		XTW.WriteElementString("key", "HostID");
		XTW.WriteElementString("string", iPhone.sHostID);
		XTW.WriteElementString("key", "Request");
		XTW.WriteElementString("string", "StartSession");

		XTW.WriteEndElement(); // dict
		XTW.WriteEndElement(); // plist
		XTW.WriteEndDocument();
		XTW.Flush();

		byte[] bXMLData = MS.GetBuffer();
		XTW.Close(); // Closes MS, too.

		PListSend(bXMLData);
		bXMLData = PListReceive();

		MS = new MemoryStream(bXMLData);
		XmlDocument XD = new XmlDocument();
		XD.XmlResolver = null; // Don't fetch DTD from web. Speeds things up tremendously.
		XD.Load(MS);
		MS.Close();

		if (XD["plist"]["dict"].SelectSingleNode("key[text()='Result']") != null
			&& XD["plist"]["dict"].SelectSingleNode("key[text()='Result']").NextSibling.InnerText == "Success")
			sSessionID = XD["plist"]["dict"].SelectSingleNode("key[text()='SessionID']").NextSibling.InnerText;
		else
		{
			Global.Log("failed!\n", true);
			throw new Exception("StartSession command was rejected.");
		}

		// Start the SSL session.
		try
		{
			SSLInOutStream = new SSLHelperStream(this.LockdownReceiveSSLCallback, this.LockdownSendSSLCallback);
			SSLConnection = new System.Net.Security.SslStream(SSLInOutStream, false,
											(s, c, ch, e) => { return true; },
											(s, t, L, r, a) => { if (L != null && L.Count > 0) return L[0]; return null; });

			X509CertificateCollection CC = new X509CertificateCollection();
			X509Certificate2 RootCertWithPrivKey = new X509Certificate2(iPhone.RootCertificate.GetEncoded());
			RootCertWithPrivKey.PrivateKey = Org.BouncyCastle.Security.DotNetUtilities.ToRSA((Org.BouncyCastle.Crypto.Parameters.RsaPrivateCrtKeyParameters)iPhone.RootKey.Private);
			CC.Add(RootCertWithPrivKey);
			SSLConnection.AuthenticateAsClient(string.Empty, CC, System.Security.Authentication.SslProtocols.Ssl3, false);
		}
		catch (Exception e)
		{
			Global.Log("failed!\n", true);
			throw e;
		}

		if (!SSLConnection.IsAuthenticated)
		{
			Global.Log("failed!\n", true);
			SSLConnection = null;
			throw new Exception("AuthenticateAsClient succeeds but IsAuthenticated is false.");
		}

		Global.Log("success!\n", true);

		//Global.Log(GetValueFromDevice("com.apple.disk_usage", "TotalDiskCapacity") + "\n\n\n");
	}

	public int StartService(string sServiceName)
	{
		Global.Log("Starting service \"" + sServiceName + "\"... ");
		MemoryStream MS = new MemoryStream();
		XmlWriter XTW = XmlWriter.Create(MS, XWS);
		byte[] bXMLData;
		
		XTW.WriteStartDocument();
		XTW.WriteDocType("plist", sApplePubID, sAppleSysID, null);
		XTW.WriteStartElement("plist");
		XTW.WriteAttributeString("version", "1.0");
		XTW.WriteStartElement("dict");

		XTW.WriteElementString("key", "Request");
		XTW.WriteElementString("string", "StartService");
		XTW.WriteElementString("key", "Service");
		XTW.WriteElementString("string", sServiceName);

		XTW.WriteEndElement(); // dict
		XTW.WriteEndElement(); // plist
		XTW.WriteEndDocument();
		XTW.Flush();

		bXMLData = MS.GetBuffer();
		XTW.Close(); // Closes MS, too.

		PListSend(bXMLData);
		bXMLData = PListReceive();
		if (CheckXMLForSuccess(bXMLData))
		{
			MS = new MemoryStream(bXMLData);
			XmlDocument XD = new XmlDocument();
			XD.XmlResolver = null; // Don't fetch DTD from web. Speeds things up tremendously.
			XD.Load(MS);
			MS.Close();

			if (XD["plist"]["dict"].SelectSingleNode("key[text()='Port']") != null)
			{
				int nPort = Int32.Parse(XD["plist"]["dict"].SelectSingleNode("key[text()='Port']").NextSibling.InnerText);
				Global.Log("success!\n", true);
				return nPort;
			}
			else
			{
				Global.Log("failed!\n", true);
				throw new Exception("StartService succeeded but no port was returned.");
			}
		}
		else
		{
			Global.Log("failed!\n", true);
			throw new Exception("Bad response to StartService message.");
		}
	}

	private string GetValueFromDevice(string sDomain, string sValueName) { return GetValueFromDevice(sDomain, sValueName, false); }
	private string GetValueFromDevice(string sDomain, string sValueName, bool bReturnXML)
	{
		if (iPhone == null || !iPhone.Usable) throw new Exception("No device ready in GetValueFromDevice.");

		MemoryStream MS = new MemoryStream();
		XmlWriter XTW = XmlWriter.Create(MS, XWS);
		XTW.WriteStartDocument();
		XTW.WriteDocType("plist", sApplePubID, sAppleSysID, null);
		XTW.WriteStartElement("plist");
		XTW.WriteAttributeString("version", "1.0");
		XTW.WriteStartElement("dict");

		if (sDomain != null)
		{
			XTW.WriteElementString("key", "Domain");
			XTW.WriteElementString("string", sDomain);
		}

		if (sValueName != null)
		{
			XTW.WriteElementString("key", "Key");
			XTW.WriteElementString("string", sValueName);
		}

		XTW.WriteElementString("key", "Request");
		XTW.WriteElementString("string", "GetValue");

		XTW.WriteEndElement(); // dict
		XTW.WriteEndElement(); // plist
		XTW.WriteEndDocument();
		XTW.Flush();

		byte[] bXMLData = MS.GetBuffer();
		XTW.Close(); // Closes MS, too.

		PListSend(bXMLData);
		bXMLData = PListReceive();
		if (bXMLData == null || bXMLData.Length == 0) return null;

		MS = new MemoryStream(bXMLData);
		XmlDocument XD = new XmlDocument();
		XD.XmlResolver = null; // Don't fetch DTD from web. Speeds things up tremendously.
		try { XD.Load(MS); }
		catch { return null; }
		MS.Close();

		if (XD["plist"]["dict"].SelectSingleNode("key[text()='Result']") != null
			&& XD["plist"]["dict"].SelectSingleNode("key[text()='Result']").NextSibling.InnerText == "Success")
		{
			if (!bReturnXML)
				return XD["plist"]["dict"].SelectSingleNode("key[text()='Value']").NextSibling.InnerText;
			else
				return XD["plist"]["dict"].SelectSingleNode("key[text()='Value']").NextSibling.InnerXml;
		}

		Global.Log("LockdownGetValueFromDevice failed to parse value from response.\n");
		return null;
	}

	// GetValueFromDevice is private (necessary?) These are public methods to
	// access certain specific device values.
	public string GetDeviceName()
	{
		return GetValueFromDevice(null, "DeviceName");
	}
	public string GetUniqueDeviceID()
	{
		return GetValueFromDevice(null, "UniqueDeviceID");
	}
	public string GetSQLPostProcessCommands()
	{
		return GetValueFromDevice("com.apple.mobile.iTunes.SQLMusicLibraryPostProcessCommands", null, true);
	}

	// Only to be called by SSLHelperStream. byte[] bData will be SSL-encrypted
	// data that needs to be passed along to the device.
	private int LockdownSendSSLCallback(byte[] bData)
	{
		if (iPhone == null || !iPhone.Usable) throw new Exception("No device ready in LockdownSendSSLCallback.");
		if (bData == null) throw new Exception("No data passed to LockdownSendSSLCallback.");
		return Send(bData);
	}

	// Only to be called by SSLHelperStream.
	private byte[] LockdownReceiveSSLCallback()
	{
		if (iPhone == null || !iPhone.Usable) throw new Exception("No device ready in LockdownReceiveSSLCallback.");
		return Receive();
	}

}

// This class takes the place of NetworkStream for use with the
// SslStream class. Instead of talking with a TCP client over the internet,
// this class redirects input to and output from the iPhone over USB.
class SSLHelperStream : MemoryStream
{
	public delegate byte[] ReadDelegate();
	public delegate int WriteDelegate(byte[] bData);

	private ReadDelegate ReadFromDevice;
	private WriteDelegate SendToDevice;

	public SSLHelperStream(ReadDelegate Read, WriteDelegate Send)
	{
		ReadFromDevice = Read;
		SendToDevice = Send;
	}

	public override void Flush()
	{
		if (SendToDevice != null)
		{
			byte[] bBuffer = GetBuffer();
			short nLength = System.Net.IPAddress.NetworkToHostOrder(BitConverter.ToInt16(bBuffer, 3));
			byte[] byPacket = new byte[nLength + 5];
			Array.Copy(bBuffer, byPacket, nLength + 5);
			SendToDevice(byPacket);
		}
		SetLength(0);
	}

	// A request from SSLStream to write SSL-encrypted data
	// (byte[] buffer) to the device.
	public override void Write(byte[] buffer, int offset, int count)
	{
		if (SendToDevice != null)
		{
			byte[] byPacket = new byte[count];
			Array.Copy(buffer, offset, byPacket, 0, count);
			SendToDevice(byPacket);
		}
	}

	// A request from SSLStream to read data from the device.
	public override int Read(byte[] buffer, int offset, int count)
	{
		// If the stream is empty, fill it by requesting a packet from the iPhone.
		if (Length == 0 && ReadFromDevice != null)
		{
			byte[] byPacket = ReadFromDevice();
			base.Write(byPacket, 0, byPacket.Length);
			Seek(0, SeekOrigin.Begin);
		}

		int nReturnValue = base.Read(buffer, offset, count);

		// If this read brought us to the end of the packet, clear the stream.
		if (Position == Length)
			SetLength(0);

		return nReturnValue;
	}

	// A request from SSLStream to read data from the device.
	public override int ReadByte()
	{
		// If the stream is empty, fill it by requesting a packet from the iPhone.
		if (Length == 0 && ReadFromDevice != null)
		{
			byte[] byPacket = ReadFromDevice();
			base.Write(byPacket, 0, byPacket.Length);
			Seek(0, SeekOrigin.Begin);
		}

		int nReturnValue = base.ReadByte();

		// If this read brought us to the end of the packet, clear the stream.
		if (Position == Length)
			SetLength(0);

		return nReturnValue;
	}
}