# 原神题解
## 考点
- 图片隐写
## 分析与解答
先用stegsolve获取一层密码，提交后发现不是flag：
![alt text](images/image1.png)

于是试试它是不是压缩包的密码，解压之后得到，发现有个图片：
![alt text](images/image2.png)
![alt text](images/image3.png)

然后调色得到：
![alt text](images/image4.png)

并且在图片后有一个隐藏的文本：
![alt text](images/image5.png)

然后将文档后缀改为zip，然后一直解密：
![alt text](images/image6.png)
![alt text](images/image7.png)
![alt text](images/image8.png)