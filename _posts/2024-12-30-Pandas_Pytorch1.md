---
layout: post
title: "[Pandas, Pytorch] 타이타닉 생존자 데이터로 머신러닝 해보기_1"
tags: [python, pandas, pytorch]
math: true
date: 2023-12-30 12:04 +0800
categories:
    - Study
toc: true
---
데이터 출처 : https://www.kaggle.com/datasets/brendan45774/test-file
* * *
## 목표
1.Pandas를 통한 기초적 데이터 전처리 방법에 대해 학습   
2.Pytorch 사용법 및 간단한 신경망 구현 및 학습 시켜보기   
* * *
# 타이타닉 예제 데이터 정리   
   
|열|의미|   
|PassengerID|탑승객 번호|   
|Survived|생존 여부. 0 == 사망, 1 == 생존|   
|Pclass|1 == 1등석, 2 == 2등석, 3 == 3등석|   
|Name|이름|   
|Sex|성별|   
|Age|나이|   
|SibSp|함께 동승한 형재자매의 수|   
|Parch|함께 동승한 부모 및 자식의 수|   
|Ticket|티켓 번호|   
|Fare|요금|   
|Cabin|호실 번호|   
|Embarked|탑승한 지역. C == 셰르부르, Q == 퀸즈타운, S == 사우스햄튼|   
   
### 생각해봐야 할 요소
1.일부 데이터에 결측값이 있음(Age, Cabin 등)   
2.학습에 불필요할 것으로 추측되는 요소들에 대한 제거가 일부 필요해보임   
3.One-Hot Encoding이 필요해 보이는 데이터들이 있음   
* * *
# 데이터 전처리
## 1.module import
```python
import numpy as np
import pandas as pd
import torch
import torch.nn as nn
import torch.optim as optim
```
Pandas, Numpy 및 Pytorch를 import 해주었다.   
## 2.데이터 불러오기
```python
titanic = pd.read_csv("tested.csv")
```

