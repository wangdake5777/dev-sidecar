# 大模型输出质量评估(POC篇)

## 数据存储

1. InputPrompt: str   # 输入LLM的提示词
2. Label: dict        # 正确答案标签 

## 采样

输入InputPrompt，由LLM生成多个回复。

## 为每个回复打分

打分分为两种方式：

1. 绝对评分：类似于让人吃东西然后评价食品，基于个人口味的主观评分。例如：Reward Model 端到端地为每个回复生成一个标量数值作为评分。

2. 相对评分：类似于先让人吃流水线的标准产物，设定标准产物的风味为1分，然后再吃其它的，提供了参考系。

对LLM回复采用绝对评分的方式时，我们遇到问题：模型学习到了好答案和坏答案的风格，但风格好的答案可能本身存在事实谬误。

我们需要采用相对评分的方式，即想办法定义一个标准答案，然后让模型生成回复，然后根据回复和标准答案(Label)的相似度进行评分，bleu和rouge做了这样的事情，在翻译任务中这有效。但对于poc代码，关键的位置哪怕只差一个字符也会导致poc失效，看上去差异更大的代码完全有可能实现相同的功能，我们不能简单地按照序列相似度进行评分，而是需要引入一些事实性判断，因此标准答案的标注不会仅仅需要poc代码，还需要一些其他的字段。

## 标准答案(Label)

1. $POC: str                    # 验证此漏洞的POC参考答案
2. $MALICIOUS_PLACEHOLDER: str  # 恶意数据的占位符，用于表达攻击者可以将这个占位符替换为一个恶意内容从而利用漏洞
3. $EXPLOIT_APPROACH: any       # 漏洞的途径，此处需要重点设计如何标注

### HTTP服务漏洞的EXPLOIT_APPROACH标注手段？

python中使用`requests`库发送HTTP请求，我们或许可以标注这些信息：

1. $TARGET_URL: str           # 存在漏洞的服务接口地址
2. $METHODS: list             # 发送数据包的方法，例如requests.post, requests.get, ..
3. $VULNERABLE_PART           # 恶意数据发送的位置，HTTP中可以大体拆分为URL, HEADER, BODY三部分
3. $PAYLOAD_REQUIREMENTS: any # 数据包需要满足的条件

有时我们可以确认发送数据包的格式，即数据包需要百分之百符合特定格式才能利用漏洞，这时判断是简单的：
- $SPECIFIC_PAYLOAD: str     # 特定格式的payload，例如 `$$$$$$`

有时我们无法确认数据包的格式，但可以确认数据包需要满足的条件，这时判断就可能只能进行模糊匹配或者相似度衡量：
- $NECESSARY_PAYLOAD: str   # 必要payload或者字段，例如{"url": "http://example.com"}
- $FORBIDDEN_PAYLOAD: str   # 不允许出现的payload或者字段，例如{"imgBase64": "..."}



#### Example 1

服务代码像这样：
```java
@PostMapping("/download")
public ResponseEntity<?> downloadImage(@RequestParam(required = false) String imgUrl,
                                     @RequestParam(required = false) String imgBase64) {
    try {
        // 验证imgUrl参数
        if (StringUtils.isEmpty(imgUrl)) {
            return ResponseEntity.badRequest().body("imgUrl不能为空");
        }

        // 如果imgBase64不为空，直接返回
        if (!StringUtils.isEmpty(imgBase64)) {
            return ResponseEntity.ok("已有图片数据，无需下载");
        }

        // 下载图片
        URL url = new URL(imgUrl);
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.setRequestMethod("GET");
```

这时如果以http://example.com为占位符，必要的payload(只有出现在URL)就可能像这样：`imgUrl=http://example.com`，禁止出现`imgBase64=xxx`相关的payload。(这需要对键-值对类型的数据的空值处理)

## 硬标准直接判断POC正确与否的模块

验证逻辑可能类似于：
```
# 验证poc目标地址
ASSERT Label.$TARGET_URL IN Response
# 验证发送数据包的方法
ASSERT Label.$HTTP_METHOD IN Extract_Method(Response)
# 验证恶意占位符
ASSERT Label.$MALICIOUS_PLACEHOLDER IN Response

...

```


## 软判断POC正确性的模块 (LLM 代码风格的优化)

1. 使用库更好， `json.dumps({'key': 'value'})` > `'{"key": "value"}'`
2. 计算结果更好， `version = 37 + 1` > `version = 38`
3. 注入点独立出来更好： 

      ```
      malicious_payload = '$dnslog'
      requests.get(f"http://sandbox-service/api?url={malicious_payload}")
      ``` 

    \> `requests.get(f"http://sandbox-service/api?url=$dnslog")`

...
