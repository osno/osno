## Our buildserver is currently running on: ##

## Current OS

> Ubuntu 22.04.1 LTS (Kernel 5.15.0) 64-bit

## Hardware requirements

> RAM:  16GB
>
> SWAP: 8GB
>
> CPU:  Multi core\thread Model
>
> HDD:  for Single Build 250GB Free, for Multibuild 500GB or more

## Git repositories involved

* [OE Alliance Core](https://github.com/oe-alliance/oe-alliance-core/tree/5.3 "OE Alliance Core") - Core framework
* [https://github.com/opendroid-Team/enigma2](https://github.com/opendroid-Team/enigma2/tree/master "openDroid Enigma2") 
* [https://github.com/stein17/Skins-for-openOPD/tree/python3)

## DOXYGEN Documentation



# Building Instructions #

1 - Install packages on your buildserver

    ```sh
    sudo apt-get install -y autoconf automake bison bzip2 chrpath coreutils cpio curl cvs debianutils default-jre default-jre-headless diffstat flex g++ gawk gcc gcc-12 gcc-multilib g++-multilib gettext git git-core gzip help2man info iputils-ping java-common libc6-dev libegl1-mesa libglib2.0-dev libncurses5-dev libperl4-corelibs-perl libproc-processtable-perl libsdl1.2-dev libserf-dev libtool libxml2-utils make ncurses-bin patch perl pkg-config psmisc python3 python3-git python3-jinja2 python3-pexpect python3-pip python-setuptools qemu quilt socat sshpass subversion tar texi2html texinfo unzip wget xsltproc xterm xz-utils zip zlib1g-dev zstd fakeroot lz4

2 - Set `python3 as preferred provider for `python`

    ```sh
    sudo update-alternatives --install /usr/bin/python python /usr/bin/python2 1

    sudo update-alternatives --install /usr/bin/python python /usr/bin/python3 2

    sudo update-alternatives --config python
    select python3
    ```

3 - Set your shell to  `/bin/bash`

    ```sh
    sudo dpkg-reconfigure dash
    When asked: Install dash as /bin/sh?
    select "NO"
    ```

4 - modify max_user_watches

    ```sh
    echo fs.inotify.max_user_watches=524288 | sudo tee -a /etc/sysctl.conf

    sudo sysctl -n -w fs.inotify.max_user_watches=524288
    ```

5 - Add user opendroidbuilder

    ```sh
    sudo adduser opendroidbuilder
    ```

6 - Switch to user opendroidbuilder

    ```sh
    su opendroidbuilder
    ```

7 - Create folder opendroid

    ```sh
8-    mkdir -p opendroid
    ```

9 - Switch to folder opendroid

    ```sh
    cd opendroid
    ```

10. Clone oe-alliance repository

    ```sh
    git clone https://github.com/oe-alliance/build-enviroment.git -b 5.3
    ```

11 - Switch to folder build-enviroment

    ```sh
    cd build-enviroment
    ```

12 - Update build-enviroment

    ```sh
    make update
    ```

13 - Finally you can start building a image

* Build an image with feed (build time 5-12h)

    ```sh
 15 -    MACHINE=sf4008 DISTRO=opendroid DISTRO_TYPE=release make image
    ```

* Build an image without feed (build time 1-2h)

    ```sh
 16 -    MACHINE=sf4008 DISTRO=opendroid DISTRO_TYPE=release make enigma2-image
    ```

* Build the feeds

    ```sh
    MACHINE=sf4008 DISTRO=opendroid DISTRO_TYPE=release make feeds
    ```

* Build specific packages

    ```sh
 17 -    MACHINE=sf4008 DISTRO=opendroid DISTRO_TYPE=release make init

    cd builds/opendroid/sf4008/

    source env.source

    bitbake nfs-utils rcpbind ...
    ```
