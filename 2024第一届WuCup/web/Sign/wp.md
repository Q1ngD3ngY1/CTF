# Sign题解
## 考点
- rce

## 分析与题解
直接提示如下：
![alt text](images/image1.png)

然后想的是以post方式提交json数据，发现没有返回，于是想到在webshell利用的地方有个passwd的东西，于是构造payload为`sgin=eval(system('cat /flag'));`，拿到flag：
![alt text](images/image2.png)