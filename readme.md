# How to build openocd in linux for windows

```bash
# for libusb
export PKG_CONFIG_PATH=/mingw64/lib/pkgconfig
./bootstrap
mkdir build
cd build
../configure --prefix=/home/Administrator/openocd/build --enable-xxlink
../configure --prefix=/home/konglei/openocd/build --enable-xxlink
../configure --prefix=/c/ENV/msys64/home/Administrator/openocd/build --enable-xxlink
make CFLAGS+="-Wno-error" -j12
make install
```
## 编译依赖库

```sh
# wget "https://gh-proxy.com/github.com/libusb/libusb/releases/download/v1.0.26/libusb-1.0.26.tar.bz2"
# tar -xjf libusb-1.0.26.tar.bz2
export LIBUSB1_SRC=$PWD/libusb-1.0.26
# wget "https://gh-proxy.com/github.com/libusb/hidapi/archive/hidapi-0.13.1.tar.gz"
# tar -xzf hidapi-0.13.1.tar.gz
export HIDAPI_SRC=$PWD/hidapi-hidapi-0.13.1
# cd hidapi-hidapi-0.13.1
# ./bootstrap
# wget "https://github.com/libconfuse/libconfuse/releases/download/v3.3/confuse-3.3.tar.xz"
# tar -xjf confuse-3.3.tar.xz
export CONFUSE_SRC=$PWD/confuse-3.3
# wget "http://www.intra2net.com/en/developer/libftdi/download/libftdi1-1.5.tar.bz2"
# tar -xjf libftdi1-1.5.tar.bz2
export LIBFTDI_SRC=$PWD/libftdi1-1.5
# wget "https://gh-proxy.com/github.com/aquynh/capstone/archive/4.0.2.tar.gz"
# tar -xzf 4.0.2.tar.gz
export CAPSTONE_SRC=$PWD/capstone-4.0.2
# wget https://gitlab.zapb.de/libjaylink/libjaylink/-/archive/0.3.1/libjaylink-0.3.1.tar.gz
# tar -xzf libjaylink-0.3.1.tar.gz
export LIBJAYLINK_SRC=$PWD/ibjaylink-0.3.1
# cd libjaylink-0.3.1
# ./autogen.sh
export LIBUSB1_CONFIG="--enable-shared --disable-static"
export HIDAPI_CONFIG="--enable-shared --disable-static --disable-testgui"
export LIBFTDI_CONFIG="-DSTATICLIBS=OFF -DEXAMPLES=OFF -DFTDI_EEPROM=OFF"
export CAPSTONE_CONFIG="CAPSTONE_BUILD_CORE_ONLY=yes CAPSTONE_STATIC=yes CAPSTONE_SHARED=no"
export LIBJAYLINK_CONFIG="--enable-shared --disable-static"
```

## 交叉编译
```bash
./contrib/cross-build.sh i686-w64-mingw32
```