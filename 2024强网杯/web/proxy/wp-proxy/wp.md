# Proxy题解
## 考点
* go代码审计
* nginx权限限制绕过
## 分析
有用的就两个文件：`proxy.conf`，`main.go`

先看一下`proxy.conf`，没有直接访问/v1权限。
```conf
server {
    listen 8000;

    location ~ /v1 {
        return 403;
    }

    location ~ /v2 {
        proxy_pass http://localhost:8769;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection $connection_upgrade;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
}
```

需要借助v2代理，即/v2/api/proxy
```go
	v2 := r.Group("/v2")
	{
		v2.POST("/api/proxy", func(c *gin.Context) {
			var proxyRequest ProxyRequest
			if err := c.ShouldBindJSON(&proxyRequest); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"status": "error", "message": "Invalid request"})
				return
			}

			client := &http.Client{
				CheckRedirect: func(req *http.Request, via []*http.Request) error {
					if !req.URL.IsAbs() {
						return http.ErrUseLastResponse
					}

					if !proxyRequest.FollowRedirects {
						return http.ErrUseLastResponse
					}

					return nil
				},
			}

			req, err := http.NewRequest(proxyRequest.Method, proxyRequest.URL, bytes.NewReader([]byte(proxyRequest.Body)))
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"status": "error", "message": "Internal Server Error"})
				return
			}

			for key, value := range proxyRequest.Headers {
				req.Header.Set(key, value)
			}

			resp, err := client.Do(req)

			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"status": "error", "message": "Internal Server Error"})
				return
			}

			defer resp.Body.Close()

			body, err := io.ReadAll(resp.Body)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"status": "error", "message": "Internal Server Error"})
				return
			}

			c.Status(resp.StatusCode)
			for key, value := range resp.Header {
				c.Header(key, value[0])
			}

			c.Writer.Write(body)
			c.Abort()
		})
	}
```

## 解答
直接构造payload：
![alt text](image.png)