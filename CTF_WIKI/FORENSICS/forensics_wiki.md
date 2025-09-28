下面给出**完整一次性通关流程**，你照着复制即可，以后任何 `.vmdk` 取证都通用。

---

## 🎯 一次性通关脚本（Kali 虚拟机）

```bash
# 0. 把 what.vmdk 拖进 Kali 桌面
# 1. 装工具（Kali 已自带可跳过）
sudo apt update && sudo apt install -y qemu-utils tree

# 2. 加载 nbd 模块
sudo modprobe nbd max_part=8

# 3. 把 vmdk 接到虚拟块设备
sudo qemu-nbd -c /dev/nbd0 ~/Desktop/what.vmdk

# 4. 创建挂载点
sudo mkdir -p /mnt/nbd0p1 /mnt/nbd0p2

# 5. 逐个试挂载（通常 p2 才是主系统）
sudo mount /dev/nbd0p1 /mnt/nbd0p1 2>/dev/null
sudo mount /dev/nbd0p2 /mnt/nbd0p2 2>/dev/null

# 6. 看目录确认
ls /mnt/nbd0p2          # 应该能看到 etc home var ...

# 7. 一键搜 flag
sudo grep -Rai "flag{" /mnt/nbd0p2 2>/dev/null | tee ~/Desktop/flag.txt

# 8. 没找到就再扫其它关键词
sudo grep -Rai "ctf{" /mnt/nbd0p2 2>/dev/null | tee -a ~/Desktop/flag.txt

# 9. 卸载
sudo umount /mnt/nbd0p1 /mnt/nbd0p2
sudo qemu-nbd -d /dev/nbd0

# 10. 查看结果
cat ~/Desktop/flag.txt
```

---

## ✅ 你现在只需

1. 把上面整块复制进终端。
2. 最后 `cat ~/Desktop/flag.txt` 就能看到 flag。
