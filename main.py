import hashlib
import logging
import os
import struct
import trace
import traceback

import frida

# 文件md5
md5 = lambda bs: hashlib.md5(bs).hexdigest()


## 设备链接
def connect_device(timeout=15):
    try:
        device = frida.get_usb_device(timeout=timeout)
    except:
        device = frida.get_remote_device()

    return device


def get_all_process(device, package_name):
    return [process for process in device.enumerate_processes() if package_name in process.name]





def process_dex_dump(session, package_name):
    # 加载脚本
    path = os.path.dirname(__file__)
    script = session.create_script(open(os.path.join(path, "agent.js")).read())
    script.load()
    # script.exports 是js提供的rpc调用方式
    dump(package_name, script.exports)


def dump(package_name, api):
    mds = []
    # 遍历dex 返回所有符合要求的内存基址和大小
    matches = api.scandex()
    print('[DEXDump]: dex list '+ str(matches))
    # 下载下来 dex文件
    for dex_info in matches:
        try:
            bs = api.memorydump(dex_info['addr'], dex_info['size'])
            md = md5(bs)
            if md in mds:
                print("[DEXDump]: Skip duplicate dex {}<{}>".format(dex_info['addr'], md))
                continue
            mds.append(md)
            if not os.path.exists("./" + package_name + "/"):
                os.mkdir("./" + package_name + "/")
            with open(package_name + "/" + dex_info['addr'] + ".dex", 'wb') as out:
                out.write(bs)
            print("[DEXDump]: DexSize={}, DexMd5={}, SavePath={}/{}/{}.dex"
                  .format(hex(dex_info['size']), md, os.getcwd(), package_name, dex_info['addr']))
        except Exception as e:
            print("[Except] - {}: {}".format(e, dex_info))


# 进入新的进程之前杀死其他服务
def stop_other(pid, processes, is_emulator=False):
    try:
        for process in processes:
            if process.pid == pid:
                if is_emulator:
                    os.system("adb shell \"su 0 kill -18 {}\"".format(process.pid))
                else:
                    os.system("adb shell \"su -c 'kill -18 {}'\"".format(process.pid))
            else:
                if is_emulator:
                    os.system("adb shell \"su 0 kill -19 {}\"".format(process.pid))
                else:
                    os.system("adb shell \"su -c 'kill -19 {}'\"".format(process.pid))
    except:
        pass


def start(package_name):
    print('[DEXDump]: package name' + package_name)
    device = connect_device()
    if device:
        # 一个包名多个进程非常正常 全部dump出来
        processes = get_all_process(device, package_name)
        for process in processes:
            try:

                print("[DEXDump]: found target [{}] {}".format(process.pid, process.name))
                stop_other(process.pid, processes)

                session = device.attach(process.pid)
                process_dex_dump(session, package_name)

                session.detach
            except Exception as e:
                # traceback.print_exc(e)
                print('[DEXDump]: Exception ' + str(e))
    else:
        raise Exception('[DEXDump]: Exception device connect fail')
    exit()


if __name__ == '__main__':
    start("cn.missfresh.application")
