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