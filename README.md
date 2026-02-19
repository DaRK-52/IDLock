# IDLock - 区块链身份认证系统

基于区块链的匿名身份认证系统，使用BBS+签名和零知识证明技术。

## 系统模型
- **用户 (User)**: 需要注册身份并申请凭证的个人，在本地生成身份陷门并基于身份陷门生成在区块链上注册的身份标识，用户拥有一系列属性（例如`{"m1": "alice", "m2": "22", "m3": "student"}`），可使用这些属性申请凭证或生成证明
- **权威机构 (Issuer)**: 负责验证用户身份并颁发属性凭证的实体，拥有一个私钥用于签发凭证，并将用户的身份标识与属性凭证绑定在一起
- **验证者 (Verifier)**: 需要验证用户身份并提供服务的实体，通过验证用户提供的零知识证明来确认用户的身份和属性凭证的有效性
- **区块链 (Blockchain)**: 作为去中心化的身份注册和验证平台，存储用户的身份标识

## 环境配置
```
docker pull sbellem/charm-crypto:4893024-python3.7-slim-buster

docker run -it -v ./:/root/test --rm sbellem/charm-crypto:4893024-python3.7-slim-buster /bin/bash

cd /root/test
```

## 运行示例
```
# 完整认证过程测试
python3 -m test.test_user
# issuer功能测试
python3 -m test.test_issuer
# verifier功能测试
python3 -m test.test_verifier
# blockchain功能测试
python3 -m test.test_blockchain
```