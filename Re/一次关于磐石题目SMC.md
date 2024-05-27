这是关于上海的磐石行动的逆向题目：

今天天气怎么样

这题目中给出的是一个32bit的程序。：
![image](https://github.com/OrangeStarOne/CTF/assets/113007326/c985076b-46dc-4640-8ce8-2bfce492a01f)


看看这到题，前面式一个正常的判断的过程，首先是输入一个字符串str是一个30长度的。flag的长度就是30，对输入的长度进行了判断，之后是一个crazy()函数，可已跟进去：
![image](https://github.com/OrangeStarOne/CTF/assets/113007326/1b9f0958-a848-4cb3-b944-82397e7ccea5)


这里就是在进行奇偶进行减法和异或的操作偶数减去索引，奇数异或索引。

下面还有一个ohh函数：
![image](https://github.com/OrangeStarOne/CTF/assets/113007326/017e8002-b823-4d58-a95e-6698cbdfe5b5)


这里就进行的了最后的判断这里与unk_4040C0进行对比：

提取出unk_4040C0的数据：

```
    0x66, 0x6B, 0x63, 0x64, 0x7F, 0x63, 0x69, 0x70, 0x57, 0x60,
    0x79, 0x54, 0x78, 0x5B, 0x6B, 0x50, 0x67, 0x54, 0x73, 0x61,
    0x7C, 0x50, 0x64, 0x48, 0x6C, 0x56, 0x7E, 0x46, 0x65, 0x60
```

下面就是写出脚本进行处理：

```
def reverse_crazy(input_str):
    result = ""
    for i in range(30):
        if i % 2 == 0:
            result += chr(ord(input_str[i]) ^ i)
        else:
            result += chr(ord(input_str[i]) + i)
    return result

# unk_4040C0的内容
unk_4040C0 = [
    0x66, 0x6B, 0x63, 0x64, 0x7F, 0x63, 0x69, 0x70, 0x57, 0x60,
    0x79, 0x54, 0x78, 0x5B, 0x6B, 0x50, 0x67, 0x54, 0x73, 0x61,
    0x7C, 0x50, 0x64, 0x48, 0x6C, 0x56, 0x7E, 0x46, 0x65, 0x60
]

# 将unk_4040C0的内容转换为字符串
input_str = "".join(chr(c) for c in unk_4040C0)

# 逆向crazy函数的变换操作
flag = reverse_crazy(input_str)

print("Flag:", flag)
# Flag: flag{how_is_the_weather_today}
```

这是个错误的flag：

其实下面才是真正的flag出现的地方

![image](https://github.com/OrangeStarOne/CTF/assets/113007326/21bf04f8-f084-47b0-a023-3f3322b7a068)


发现这里是smc操作其实就是代码加密混淆了：

这里就是将原有的函数进行了异或0x41的操作，要想得到my_function这个函数，就需要再次异或回去。本想着直接动调恢复到源码，结果发现，这里的调用函数的思路不同，上面的动调恢复到方法只适合在这里还是函数的时候，而这里是当作偏移量传递给了lpAddress这个。这样就直接静态调试好了，直接进行异或的操作：在IDA中运行脚本：

这里可以自己计算，也可以拿脚本计算

```
star = 0x403000
end = star+0x183
for i in range(star,end+1):
	patch_byte(i,get_wide_byte(i)^0x41)
print("解密完成")
```

![image](https://github.com/OrangeStarOne/CTF/assets/113007326/80c1984d-0f99-4018-9d3c-1300fdfc957c)


这是开始第地方，查看它的起始地址：

![image](https://github.com/OrangeStarOne/CTF/assets/113007326/bef16917-fef3-4a3a-a29f-575fe42bded4)


上面是异或前的样子，下面是运行脚本后的样子：

![image](https://github.com/OrangeStarOne/CTF/assets/113007326/ff7f9b04-a9fb-4ea1-9855-486970aaa1cb)

使其变成C语言：按c键

![image](https://github.com/OrangeStarOne/CTF/assets/113007326/edfae6f1-5e51-4965-8c29-8f810fc759f0)


先是Force在是yes：

![image](https://github.com/OrangeStarOne/CTF/assets/113007326/feff52ea-6396-4810-b636-9bf61c2a730b)


之后是按下p键：

![image](https://github.com/OrangeStarOne/CTF/assets/113007326/db22ac28-cc43-44d5-8098-e38b7bb7b258)


这里就是异或后的函数，这时就可以F5了：

```
void __cdecl __noreturn my_function(const char *a1)
{
  unsigned int v1; // eax
  char Str[50]; // [esp+16h] [ebp-2D2h] BYREF
  int v3[30]; // [esp+48h] [ebp-2A0h] BYREF
  unsigned __int8 v4[256]; // [esp+C0h] [ebp-228h] BYREF
  char v5[256]; // [esp+1C0h] [ebp-128h] BYREF
  unsigned int v6; // [esp+2C0h] [ebp-28h]
  unsigned int j; // [esp+2C4h] [ebp-24h]
  int v8; // [esp+2C8h] [ebp-20h]
  int i; // [esp+2CCh] [ebp-1Ch]

  puts("please input your True flag:");
  scanf("%40s", Str);
  v6 = strlen(Str);
  if ( v6 != 30 )
  {
    puts("Wrong!");
    exit(0);
  }
  qmemcpy(v3, &unk_404040, sizeof(v3));
  memset(v4, 0, sizeof(v4));
  memset(v5, 0, sizeof(v5));
  v1 = strlen(a1);
  xxx_init(v4, (unsigned __int8 *)a1, v1);
  for ( i = 0; i <= 255; ++i )
    v5[i] = v4[i];
  xxx_crypt(v4, (unsigned __int8 *)Str, v6);
  v8 = 1;
  for ( j = 0; ; ++j )
  {
    if ( j >= v6 )
      goto LABEL_11;
    if ( (unsigned __int8)Str[j] != v3[j] )
      break;
  }
  v8 = 0;
LABEL_11:
  if ( v8 )
    puts("Good! have a beautiful day for you!");
  else
    puts("May be try again?");
  exit(0);
}
```

这就是完整的my_function(const char *a1)函数：

这里有一个参数：a1是上一次加密后的一个字符串：flag{how_is_the_weather_today}

在这个函数中可以看到：

![image](https://github.com/OrangeStarOne/CTF/assets/113007326/311e19e5-80b8-40c5-a819-55687deebd92)


有两个函数，一个是初始化，一个是真正的加密，跟进去：

![image](https://github.com/OrangeStarOne/CTF/assets/113007326/4373d796-0683-4c93-bbc9-b1c89922d382)


这里是想讲先是构造一个0，255的数组，后面就是进行值与值的交换。

![image](https://github.com/OrangeStarOne/CTF/assets/113007326/62b2a5c0-f2dc-4ca6-9a69-2a58fd393b95)


这里主要的就是进行了异或的操作，最终得脚本：

```
v3 = [0x4D, 0xD8, 0x76, 0x2D, 0x0C, 0x26, 0x0C, 0x53, 0xDA, 0xC0, 
      0x17, 0x37, 0x8C, 0xD7, 0xF3, 0xD9, 0xD0, 0x46, 0x2B, 0x15,
      0x98, 0x67, 0xF1, 0xAD, 0xA6, 0x0E, 0x7C, 0x66, 0x90, 0x7F
    ]
seed = "flag{how_is_the_weather_today}"

def xxx_init(seed):
    a1 = list(range(256))
    j = 0
    for i in range(256):
        j = (j + a1[i] + ord(seed[i % len(seed)])) % 256
        a1[i], a1[j] = a1[j], a1[i]
    return a1

def xxx_crypt(a1, data):
    i = j = 0
    out = []
    for c in data:
        i = (i + 1) % 256
        j = (j + a1[i]) % 256
        a1[i], a1[j] = a1[j], a1[i]
        out.append(c ^ a1[(a1[i] + a1[j]) % 256])
    return bytes(out)

a1 = xxx_init(seed)

flag = xxx_crypt(a1, bytes(v3))
print(flag.decode('utf-8'))
# flag{This_is_a_beautiful_day!}
```

这里得v3的值unk_404040：

```
v3 = [0x4D, 0xD8, 0x76, 0x2D, 0x0C, 0x26, 0x0C, 0x53, 0xDA, 0xC0, 
      0x17, 0x37, 0x8C, 0xD7, 0xF3, 0xD9, 0xD0, 0x46, 0x2B, 0x15,
      0x98, 0x67, 0xF1, 0xAD, 0xA6, 0x0E, 0x7C, 0x66, 0x90, 0x7F
    ]
```
