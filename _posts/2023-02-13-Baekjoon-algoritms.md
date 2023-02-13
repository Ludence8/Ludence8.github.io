---
layout: post
title: "백준 풀이 주요 알고리즘 정리"
tags: [Baekjoon, algorithm]
math: true
date: 2023-02-13 12:04 +0800
categories:
    - Baekjoon
toc: true
---
백준에서 문제를 풀어보니 자주 보이는 문제 유형들에 사용되는 알고리즘을 정리할 수 있을 것 같다는 생각이 들었다.

그래서 코딩 테스트, 백준 문제풀이 등에서 자주 보이던 유형들을 정리해보려고 한다.
(계속 공부해 나가는 과정에서 업데이트 할 수 있다면 할 예정.)

* * *
# 1. 브루트포스 알고리즘
가장 단순한 방법이다. 바로 모든 경우의 수를 다 넣어보는 단순무식한 방법이다. 4자리 숫자 자물쇠 번호를 맞추는 가장 쉬운 방법이 무엇일까? 바로 0000부터 9999까지 다 넣어보면 되는 것이다. 이 방법이 바로 브루트포스 알고리즘이다.  

[1059번](https://www.acmicpc.net/problem/1059)   
[1233번](https://www.acmicpc.net/problem/1233)   
등 문제를 브루트포스 알고리즘으로 풀 수 있다.

* * *
# 2. 그리디 알고리즘
그리디 알고리즘은 브루트포스 알고리즘과 비슷한 알고리즘이다. 하지만 브루트포스 알고리즘은 모든 경우를 다 본다면 그리디 알고리즘은 매 순간마다 자기에게 가장 이득이 되는 선택을 취하게 된다.   
[1417번](https://www.acmicpc.net/problem/1417)   
[2839번](https://www.acmicpc.net/problem/2839)   
등 문제를 그리디 알고리즘으로 풀 수 있다.

* * *
# 3. DFS와 BFS 
DFS와 BFS는 그래프 탐색 알고리즘이다.    
DFS는 Deep-First Search의 줄임말로 그래프의 노드와 다음 노드를 넘어갈 때 해당 노드의 하위 노드까지 완벽히 탐색한 뒤 다음 노드로 넘어가는 것이다.   
그리고 BFS는 Breadth-First Search의 줄임말로 그래프의 갈림길이 발생할 때마다 모든 경우를 넓게 탐색한 뒤 다음으로 넘어가게 된다.   
   
말로는 이해가 힘들어 실제 트리를 통해 탐색 결과를 비교해보면   
![제목](\assets\tree.png "출처 : 위키피디아"){: width="40%" height="40%"}   
해당 그래프를 DFS를 통해 탐색할 경우   

2 > 7 > 2 > 6 > 5 > 11 > 5 > 9 > 4   

의 순서로 탐색을 진행할 것이다.   
하지만 BFS로 탐색할 경우   

2 > 7 > 5 > 2 > 6 > 9 > 5 > 11 > 4   

의 순서로 탐색을 한다는 차이점이 있다.   

DFS의 구현은 일반적으로 재귀를 통하여 구현한다.

```python
def dfs(start):
  visited[start] = 1
  print(start, end=" ")

  for i in graph[start]:
    if not visited[i]:
      dfs(i)
```
와 같은 형태로 DFS를 구현할 수 있다.

BFS의 구현은 queue 자료구조를 통해 구현한다.
```python
def bfs(start):
  queue = [start]
  visited[start] = True
  while queue:
    v = queue.pop(0)
    print(v, end=" ")
    for i in graph[v]:
      if not visited[i]:
        visited[i] = True
        queue.append(i)
```
와 같은 형태로 BFS를 구현할 수 있다.

DFS는 그래프의 모든 경우를 하나하나 탐색해야할 때, BFS는 그래프 내의 최단 거리를 찾아야할 때 자주 사용된다.

[2644번](https://www.acmicpc.net/problem/2644)   
[1260번](https://www.acmicpc.net/problem/1260)   
등 문제를 DFS 알고리즘으로 풀 수 있다.