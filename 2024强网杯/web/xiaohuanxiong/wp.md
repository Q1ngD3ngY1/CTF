# xiaohuanxiong题解
## 考点
* 管理后台泄露
* 命令执行

## 分析与解答
扫目录得到`/admin`：
![](jpgs/image1.png)

发现是一个管理后台，然后尝试登陆(爆破)，发现没成功，于是又基于/admin再次扫目录，得到如下结果：
![alt text](jpgs/image2.png)

访问`/admin/admins.html`，在支付管理处发现可上传一句话木马的地方：
![alt text](jpgs/image3.png)

然后执行命令，获取flag：
![alt text](jpgs/image4.png)