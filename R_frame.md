# POC 标注框架


## 输入
- 用户prompt
- POC参考答案
- 大模型回复

## 标注项
输入：用户prompt，POC参考答案
1. POC参考答案
2. 恶意数据的占位符（用于表达攻击者可以将这个占位符替换为一个恶意内容从而利用漏洞）
3. TARGET_URL
4. HTTP method（requests.post, requests.get, ..）
5. 注入位置（恶意数据的发送位置）：URL\HEADER\BODY
6. PAYLOAD_REQUIREMENTS（数据包需要满足的条件）：
   - 有时我们可以确认发送数据包的格式，即数据包需要百分之百符合特定格式才能利用漏洞，这时判断是简单的：SPECIFIC_PAYLOAD，例如 $$$$$$
   - 有时我们无法确认数据包的格式，但可以确认数据包需要满足的条件，这时判断就可能只能进行模糊匹配或者相似度衡量：
     - NECESSARY_PAYLOAD，例如`{"url": "http://example.com"}`
     - FORBIDDEN_PAYLOAD，例如`{"imgBase64": "..."}`

### 示例代码
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

例如在上述代码中，如果以`http://example.com`为占位符：
- 必要的payload（只能出现在URL参数中）：`imgUrl=http://example.com`
- 禁止出现的payload：`imgBase64=xxx`相关的payload
（这需要对键-值对类型的数据的空值处理）

7. HTTPS 证书验证（verify=True/False）（用户没提到，则不标注）
8. 打印响应信息：包括 status_code、content、和 text

## 筛选
输入：标注项，大模型生成的多个回复
### 第一层：硬标准
不通过就淘汰

1. 验证使用 requests 库来发送请求
2. 验证poc目标地址
3. 验证HTTP方法
4. 验证恶意占位符
5. 验证注入位置
6. 验证是否出现forbidden_payload（需要区分payload本体、注释/示例、代码逻辑等不同用途的字符串，只检查payload本体）

### 第二层：软判断
基于大模型给出的POC代码进行打分，最后综合各部分得分判断POC的优劣

1. 注入点独立出来
   - 满分 (1.0)：POC 将恶意数据或可注入部分提取到单独变量中，如：
     ```python
     malicious_payload = '$dnslog'
     requests.get(f"{TARGET_URL}?data={malicious_payload}")
     ```
   - 部分分 (0.5)：硬编码在字符串中，但仍显式可见占位符，或者注释/变量命名中有明显提示
   - 最低 (0.0)：完全看不出可注入部分或写死在请求里，无法更换

2. HTTPS 证书验证一致
   - 满分 (1.0)：显式地写明 verify=True 或 verify=False并且与标记项一致
   - 部分分 (0.5)：没有写明 verify=，默认跟随系统，脚本可用但不够明确
   - 最低 (0.0)：因为种种原因导致 HTTPS 不可用/报错，或者逻辑中混乱

3. 打印所需响应信息
   - 满分 (1.0)：能打印出 status_code，content，text；或者至少打印出足以判断漏洞利用成败的关键信息
   - 部分分 (0.5)：只打印其中一项或只简短地输出部分信息
   - 最低 (0.0)：完全无任何输出，让测试者无法得知利用结果

4. NECESSARY_PAYLOAD相似度（用rouge指标计算）
   - 得分范围 [0,1]：
     - 1.0：与"参考载荷"在关键结构和占位符位置上一致或高度相似
     - 0.0：差异极大，无法视为等效 payload
     - 中间值则根据相似度进行映射

5. 回显内容检查
   - 满分 (1.0)：POC 中对响应做了后续判断（如 `if "xxe success" in response.text:`）
   - 较高分 (0.8)：虽然没有逻辑判断，但起码打印了完整响应
   - 最低 (0.0)：什么都不打印，也不检验，导致无法确认漏洞利用成功与否

6. 使用库更好
   - 满分 (1.0)：尽量使用官方库函数，如 `json.dumps(...)`，而非手写字符串
   - 部分分 (0.5)：手写 JSON/XML 字符串但是能正常工作，缺乏可扩展性
   - 最低 (0.0)：错误地拼装或者严重依赖字符串拼接，难以维护或易出错

7. 计算得出的结果更好
   - 满分 (1.0)：能做合理的动态计算，如 `version = 37 + 1`
   - 最低 (0.0)：完全硬编码，或写死关键逻辑，无弹性
   - 注：若POC不涉及数字/版本处理，按1.0计分

8. 有注释且简洁
   - 满分 (1.0)：对关键步骤均有简要注释说明
   - 部分分 (0.5)：有少量注释，或注释过于冗长零散
   - 最低 (0.0)：完全无注释或注释严重误导

9. 引号规范
   - 满分 (1.0)：优先使用单引号/双引号
   - 中分 (0.5)：混合使用多种引号，或局部无规律
   - 最低 (0.0)：广泛滥用三引号/反斜杠转义，让代码难读

## TOPSIS 评分方法

TOPSIS（Technique for Order Preference by Similarity to an Ideal Solution）用于对第二层软判断进行综合评分：

1. 采样：输入用户Prompt，由LLM生成多个POC

2. 评分：对标准POC和大模型生成的POC进行上述9项指标评分

3. 定义参考点：
   - 理想解(Ideal)：poc参考答案的分数
   - 负理想解(Nadir)：各指标在当前批次POC中的最低分数

4. 计算距离：
   ```
   D+ = √∑(xi - xiideal)²  # 与理想解的距离
   D- = √∑(xi - xinadir)²  # 与负理想解的距离
   ```

5. 计算TOPSIS得分：
   ```
   S = D- / (D+ + D-)  # 得分范围[0,1]
   ```
   当大模型POC越逼近理想解时，D+越小、D-越大，S越接近1
