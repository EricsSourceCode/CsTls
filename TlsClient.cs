/*
Old obsolete stuff.


// Copyright Eric Chauvin 2024.



// This is licensed under the GNU General
// Public License (GPL).  It is the
// same license that Linux has.
// https://www.gnu.org/licenses/gpl-3.0.html




using System;
// using System.Text;
using System.Threading;
using System.Net.Sockets;



// namespace


class TlsClient
{
  private NetworkStream NetStream;
  private TcpClient Client;
  private string StatusString = "";
  private ECTime LastReadWriteTime;
  private byte[] RawBuffer;
  private int RawBufferLast = 0;
  private const int MaximumBufferLength = 1024 * 1024 * 64;
  // private int PayloadSize = 0;
  private int AtSymbolPosition = 0;
  private string Command = "";
  private string PayloadString = "";
  // private byte[] PayloadBuffer;




  internal TlsClient()
    {
    Client = new TcpClient();
    Client.ReceiveTimeout = 45 * 1000;
    Client.SendTimeout = 30 * 1000;
    LastReadWriteTime = new ECTime();
    LastReadWriteTime.SetToNow();
    }




  internal void FreeEverything()
    {
    if( NetStream != null )
      {
      NetStream.Close();
      NetStream = null;
      }

    if( Client != null )
      {
      Client.Close();
      Client = null;
      }
    }



  internal string GetStatusString()
    {
    string Result = StatusString;
    StatusString = "";
    return Result;
    }



  internal double GetLastReadWriteTimeSecondsToNow()
    {
    return LastReadWriteTime.GetSecondsToNow();
    }




  internal bool IsShutDown()
    {
    if( Client == null )
      return true;

    if( !Client.Connected )
      {
      FreeEverything();
      return true;
      }

    return false;
    }



  private int GetAvailable()
    {
    if( IsShutDown())
      return 0;

    try
    {
    return Client.Available;
    }
    catch( Exception )
      {
      FreeEverything();
      return 0;
      }
    }




  internal bool Connect( string ServerIP ) // , int ServerPort )
    {
    try
    {
    Client.Connect( ServerIP, 2016 );
    }
    catch( Exception Except )
      {
      StatusString += "Could not connect to the server: " + ServerIP + "\r\n";
      StatusString += Except.Message + "\r\n";
      return false;
      }

    // Apparently it might be a problem to send something right
    // after it connects.  So give it 200 milliseconds.
    Thread.Sleep( 200 );

    try
    {
    NetStream = Client.GetStream();
    }
    catch( Exception Except )
      {
      StatusString += "Could not connect to the server (2): " + ServerIP + "\r\n";
      StatusString += Except.Message + "\r\n";
      NetStream = null;
      return false;
      }

    LastReadWriteTime.SetToNow();
    return true;
    }




  private bool WaitForData()
    {
    try
    {
    // Wait while data is not yet here.
    if( DataIsAvailable() )
      return true;

    Thread.Sleep( 100 );

    if( DataIsAvailable() )
      return true;

    return false;

    }
    catch
      {
      return false;
      }
    }




  private bool DataIsAvailable()
    {
    if( NetStream == null )
      return false;

    try
    {
    if( NetStream.DataAvailable )
      return true;

    return false;

    }
    catch
      {
      FreeEverything();
      return false;
      }
    }




  internal bool SendBuffer( byte[] Buffer )
    {
    if( IsShutDown())
      return false;

    if( NetStream == null )
      {
      StatusString += "NetStream is null in SendBuffer().";
      return false;
      }

    try
    {
    NetStream.Write( Buffer, 0, Buffer.Length );
    }
    catch
      {
      StatusString += "Could not send Buffer.";
      return false;
      }

    LastReadWriteTime.SetToNow();
    return true;
    }



  internal void ReadToRawBuffer()
    {
    if( IsShutDown())
      return;

    try
    {
    // This only knows if it's connected as of the last socket operation.
    if( !Client.Connected )
      {
      FreeEverything();
      return;
      }

    if( 0 == GetAvailable())
      return;

    if( NetStream == null )
      NetStream = Client.GetStream();

    if( !DataIsAvailable() )
      return;

    byte[] RawData = new byte[1024 * 64];

    // int TotalRead = 0;
    for( int Count = 0; Count < 10; Count++ )
      {
      if( !DataIsAvailable() )
        break;

      int BytesRead = NetStream.Read( RawData, 0, RawData.Length );
      if( BytesRead == 0 )
        break;

      AddToRawBuffer( RawData, BytesRead );
      }

    LastReadWriteTime.SetToNow();

    }
    catch( Exception Except )
      {
      StatusString += "Exception in ReadToInBuffer():\r\n";
      StatusString += Except.Message + "\r\n";
      FreeEverything();
      return;
      }
    }



  private bool AddToRawBuffer( byte[] RawData, int HowMany )
    {
    try
    {
    if( (RawBufferLast + HowMany + 1) >= MaximumBufferLength )
      {
      // Here's a way to kill the server by making it allocate too much RAM.
      // If a lot of these requests come in quickly, that allocates RAM.
      FreeEverything();
      return false;
      }

    if( RawBuffer == null )
      RawBuffer = new byte[1024 * 16];

    if( (RawBufferLast + HowMany + 1) >= RawBuffer.Length )
      Array.Resize(ref RawBuffer, RawBuffer.Length + (1024 * 256));

    for( int Count = 0; Count < HowMany; Count++ )
      {
      RawBuffer[RawBufferLast] = RawData[Count];
      RawBufferLast++;
      }

    return true;

    }
    catch
      {
      FreeEverything();
      return false;
      }
    }




  internal bool GetOuterHeaderFromRawData()
    {
    try
    {
    if( RawBuffer == null )
      return false;

    // ":Get-Public-Key;0@";
    // Or :Station Name;12345@
    if( RawBufferLast < (16 + 5) )
      return false;

    int HowMany = 10000;
    if( HowMany > RawBufferLast )
      HowMany = RawBufferLast;

    byte[] HeadingBuffer = new byte[HowMany - 16];

    if( !OuterAESEncrypt.CFBDecrypt( RawBuffer, HeadingBuffer, HowMany ))
      {
      StatusString += "CFBDecrypt returned false in GetOuterHeaderFromRawData().";
      return false;
      }

    string Header = UTF8Strings.BytesToString( HeadingBuffer, HowMany );
    if( Header.Length < 5 )
      return false;

    if( Header[0] != ':' )
      {
      StatusString += "GetOuterHeaderFromRawData() had corrupt outer data at position zero.";
      FreeEverything();
      return false;
      }


    if( !Header.Contains( "@" ))
      {
      // If it has received at least 100 bytes.
      if( HowMany == 100 )
        {
        StatusString += "GetOuterHeaderFromRawData() no @ character at 100.";
        FreeEverything();
        }

      return false;
      }

    StatusString += " Outer Header: " + Header;

    string[] SplitS = Header.Split( new Char[] { '@' } );
    if( SplitS.Length < 1 )
      {
      StatusString += "GetOuterHeaderFromRawData() SplitS.Length < 1.";
      FreeEverything();
      return false;
      }

    AtSymbolPosition = SplitS[0].Length;
    if( AtSymbolPosition < 4 )
      {
      StatusString += "GetOuterHeaderFromRawData() AtSymbolPosition < 4.";
      FreeEverything();
      return false;
      }

    // ":Get-Public-Key;0@";
    if( SplitS[0].Contains( ":Get-Public-Key;" ))
      {
      Command = "Get-Public-Key";
      PayloadString = "";
      // string PubKey = ":Get-Public-Key;0@" + MForm.GlobalProps.GetRSAPubKeyN() + "@";
      if( SplitS.Length < 2 )
        {
        StatusString += "GetOuterHeaderFromRawData() SplitS.Length < 2. No Payload string.";
        FreeEverything();
        return false;
        }

      PayloadString = SplitS[1].Trim();
      return true;
      }

    if( SplitS[0].Contains( ":Get-Valid-Station;" ))
      {
      Command = "Get-Valid-Station";
      PayloadString = "";
      if( SplitS.Length < 2 )
        {
        StatusString += "GetOuterHeaderFromRawData() SplitS.Length < 2. No Payload string for valid station.";
        FreeEverything();
        return false;
        }

      // Animas 2:Yes
      PayloadString = SplitS[1].Trim();
      return true;
      }





//////////////////
    string[] SplitHeader = SplitS[0].Split( new Char[] { ';' } );
    if( SplitHeader.Length < 2 )
      {
      MForm.ShowBinaryListenerFormStatus( "GetOuterHeaderFromRawData() SplitHeader.Length < 2." );
      FreeEverything();
      return false;
      }

    // StationName = SplitHeader[0].Replace( ":", "" );

    string TempN = SplitHeader[1].Replace( ",", "" );
    PayloadSize = Int32.Parse( TempN );
/////////////////////



    return true;

    }
    catch( Exception Except )
      {
      StatusString += "Exception in GetOuterHeaderFromRawData()\r\n";
      StatusString += Except.Message;
      FreeEverything();
      return false;
      }
    }



  internal string GetCommand()
    {
    return Command;
    }



  internal string GetPayloadString()
    {
    return PayloadString;
    }




} // Class

*/