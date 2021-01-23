# CC:Steganography
---
---
---
## Steghide
---
* Only for jpg files

```bash
$ sudo apt install steghide
$ steghide --extract -sf jpeg1.jpeg -p password123
```
---

## zsteg
---
* For png (also bmp), like steghide

```bash
$ sudo gem install zsteg
$ zsteg png1.png -a
```
---

## exiftool
---
* View and edit metadata

```bash
$ exiftool jpeg3.jpeg
```
---

## Stegoveritas
---
* Supports almost every format, a lot of different tests
* Has a lot of possible parameters and flags
```bash
$ pip3 install stegoveritas
$ stegoveritas_install_deps

$ stegoveritas -extract_frames jpeg2.jpeg
```
---

## Sonic Visualiser
---
* Layer -> Add Spectrogram
---

## Final challenge
---
### Key 1 - jpeg image
---
* Running exiftool tells us that the document name is "passowrd=admin"
* Run steghide with that password
```bash
$ wget "http://IP/images/exam1.jpeg"
$ exiftool exam1.jpeg
$ steghide --extract -p admin -sf exam1.jpeg
```
---

### Key 2 - wav audio file
---
* Run Sonic Visualiser, find link to imgur
* Download that image, find key using zsteg
```bash
$ wget "https://i.imgur.com/KTrtNI5.png"
$ zsteg chal2.png -a
```
---

### Key 3 - QRcode
---
* zbarimg reads qr codes
* The QRcode can't be read
* Use stegoveritas to generates different versions of the image, in hopes that one will be readable
```bash
$ sudo apt-get install zbar-tools
$ wget "https://IP/images/qrcode.png"

$ stegoveritas qrcode.png
$ cd results
$ find . | grep qr | xargs zbarimg
```
