Secure Chat GUI - Instructions & Usage Guide

This guide provides detailed steps on how to set up, use, and troubleshoot the Secure Chat GUI for Windows.
Installation
1. Prerequisites

    Windows 10 or 11
    MinGW-w64 (for compilation)
    WSL (if using Linux to compile for Windows)
    Git (optional, for version control)

2. Clone the Repository

If using Git, run the following commands:

git clone https://github.com/your-repo-name/secure-chat-gui.git
cd secure-chat-gui

3. Compile the Code (MinGW-w64)

Run the following command inside WSL or Windows Command Prompt:

x86_64-w64-mingw32-gcc windows_sec_msg.c -o secure_chat.exe -lws2_32 -lsecur32 -lcrypt32 -lgdi32 -mwindows

This will generate the secure_chat.exe file.
How to Use the Secure Chat GUI
1. Open Two Instances

    Open two instances of secure_chat.exe.
    One instance will act as the server.
    The other instance will act as the client.

2. Start the Server

    In one of the instances:
        Enter 127.0.0.1 in the IP Address field.
        Click "Wait" to start the server.
        A pop-up window will display the chosen port number, which is randomly selected between 4000 and 5000.
        The port number is automatically copied to the clipboard.

3. Connect the Client

    In the second instance:
        Enter 127.0.0.1 in the IP Address field.
        Paste the port number into the Port field.
        Click "Connect" to establish a connection.

4. Start Chatting

    Type a message in the Message field.
    Click "Send" to send the message.
    Messages will appear in the Chat box on both instances.

Features

    Modern GUI with a dark theme
    Server automatically assigns a port (4000-5000)
    Server port is automatically copied to the clipboard
    Fully functional bidirectional chat
    Error handling for connection failures
    Message input field clears after sending

Troubleshooting
Bind Failed: Another Process May Be Using This Port

To check which process is using the port, run:

netstat -ano | findstr :4444

Replace 4444 with the port number mentioned in the error message.

To stop the process using the port, run:

taskkill /PID <PROCESS_ID> /F

Replace <PROCESS_ID> with the number from netstat.
Client Fails to Connect

    Ensure the correct port number is entered in the client.
    Restart both the server and client, then try again.

No Messages Being Sent or Received

    Verify that the server and client are connected.
    Check firewall settings to allow communication.

License

This project is open-source under the MIT License.
Future Improvements

    User authentication (password-based login)
    Support for multiple client connections
    End-to-end encryption for secure messaging

Support

For issues, open a GitHub Issue or contact via email: keatonmott123@gmail.com
