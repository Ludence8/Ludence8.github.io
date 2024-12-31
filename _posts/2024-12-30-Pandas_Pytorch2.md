---
layout: post
title: "[Pandas, Pytorch] 타이타닉 생존자 데이터로 머신러닝 해보기_2"
tags: [python, pandas, pytorch]
math: true
date: 2023-12-31 12:04 +0800
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
## 3.데이터 가공   
데이터를 보았을 떄 이름, 승객 번호, 티켓 번호는 불필요해 보이고, 호실 번호 역시 결측값이 많고 불필요해 보여 해당 열들을 제거해주었다.
```python
titanic = titanic.drop(columns=["Name", "Ticket", "PassengerId", "Cabin"])
```   
이후 성별, 탑승지 열에 대하여 One-Hot Encoding이 필요할 듯 하여 처리해준 뒤 FloatTensor로 변환해줄 것이기 때문에 Bool 값에 대하여 1과 0으로 대체해주었다. 또한 결측치가 있는 값들은 평균으로 대체해주었다.   
```python
titanic = pd.get_dummies(titanic, columns=["Sex", "Embarked"], drop_first=True)

titanic["Sex_male"] = titanic["Sex_male"].map({True:1, False:0})
titanic["Embarked_Q"] = titanic["Embarked_Q"].map({True:1, False:0})
titanic["Embarked_S"] = titanic["Embarked_S"].map({True:1, False:0})

titanic.fillna(titanic.mean(), inplace=True)
```   
마지막으로 종속변수는 생존 여부이므로 해당 열과 다른 독립변수들을 분리했다.   
```python
X = torch.tensor(titanic.drop(columns="Survived").to_numpy(), dtype=torch.float32)
Y = torch.tensor(titanic["Survived"].to_numpy(), dtype=torch.float32).unsqueeze(1)
```   
이때 각 Tensor의 차원 크기가 맞지 않으므로 unsqueeze를 통해 맞춰주었다.   
## 4. 학습 데이터와 테스트 데이터 분리
다음으로 학습 데이터와 평가를 위한 테스트 데이터를 분리했다. 이때 분리 비율은 8:2로 분리하였다.   
   
먼저 파일의 길이만큼 인덱스를 생성한 후 해당 인덱스의 80%를 무작위로 추출했다.   
```python
size = int(X.shape[0] * 0.8)
test_indices = torch.randperm(X.shape[0])
```   
이후 추출한 사이즈만큼 독립 변수와 종속 변수를 분리해준다.   
```python
train_index = test_indices[:size]
test_index = test_indices[size:]

X_train, X_test = X[train_index], X[test_index]
Y_train, Y_test = Y[train_index], Y[test_index]
```   

