# RNode_Halow_OTA_Flasher
GUI flasher for https://github.com/I-AM-ENGINEER/RNode_Halow_Firmware

## Guide

### Before flashing

Recommended to disassemble one of the devices and make a dump of the SPI flash. During the flashing process, do not turn off the power. For the first flash to work correctly, the device must be connected to the local network with the PC and be able to obtain an IP address from a DHCP server on the same network. If the device cannot get an IP address, the flashing process will not complete, and a repeat flash will be required.

### Flashing

1) Choose the firmware version to install, which will be automatically downloaded from GitHub, or select a local firmware file.
2) Select the device to flash from the list; the HGIC type refers to devices with the original firmware.
3) Start the flashing process.
4) Once the console displays the message "OK flash done," the firmware has been successfully written.

## Инструкция

### Перед прошивкой

Рекомендуется разобрать одно из устройств и сделать дамп SPI флеш-памяти. Во время процесса прошивки не отключать питание. Для корректной первой прошивки устройство должно быть подключено к локальной сети с ПК и иметь возможность получить IP-адрес от DHCP-сервера в этой сети. Если устройство не сможет получить IP-адрес, процесс прошивки не завершится, и потребуется повторная прошивка.

### Прошивка

1) Выберите версию прошивки для установки, которая будет автоматически скачана с GitHub, или выберите локальный файл прошивки.
2) Выберите устройство для прошивки из списка; тип HGIC относится к устройствам с оригинальной прошивкой.
3) Запустите процесс прошивки.
4) Как только в консоли появится сообщение "OK flash done", прошивка успешно записана.

<img width="1400" height="1026" alt="image" src="https://github.com/user-attachments/assets/0e1b243b-f1b3-4c7e-a34e-79f845c163ed" />

### Build

#### Windows
0) Install python
1) Download [Download repo from GitHub](https://github.com/I-AM-ENGINEER/RNode_Halow_OTA_Flasher/archive/refs/heads/main.zip)
2) Unpack and run `build_win.bat`

Result will be in dist folder

#### Linux

1) Clone repo: `git clone https://github.com/I-AM-ENGINEER/RNode_Halow_OTA_Flasher && cd RNode_Halow_OTA_Flasher`
2) Add execulable flag: `chmod +x build_linux.sh`
3) Start build process: `build_linux.sh`

Result will be in dist folder
