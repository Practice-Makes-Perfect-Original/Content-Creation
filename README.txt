### For [sec_msg.c & windows_sec_msg.c]
>compile on linux:
open a terminal
locate sec_msg.c
compile:>

	gcc sec_msg.c -o secure_chat -pthread -lssl -lcrypto



>compile on windows host:

install mingw
navigate to windows_sec_message.c in mingw
run> x86_64-w64-mingw32-gcc windows_sec_msg.c -o secure_chat.exe -lws2_32 -lsecur32 -lcrypt32 -lgdi32 -mwindows
