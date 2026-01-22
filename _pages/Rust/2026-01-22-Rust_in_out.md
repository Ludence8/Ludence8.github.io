---
title: "러스트 표준 입출력 방법 정리"
tags: [Rust, Baekjoon]
toc: true
math: true
date: 2026-01-22 11:00 +0800
thumbnail: "/image/image36.jpg"
---
_최근에 러스트를 공부하기 시작하면서 러스트로 백준을 풀어보려 하고 있다. 이 과정에서 러스트의 입출력은 다른 언어보다 조금 더 복잡하다고 느끼고 있다. 그래서 개인적인 기록 용도로 입출력 방법을 정리해두고자 한다._
## 입력
### 한 줄 입력
```rust
use std::io::{self, Read};

fn main() {
    let mut input = String::new();
    io::stdin().read_line(&mut input).unwrap();
}
```
String 변수를 하나 만든 뒤 해당 변수 값을 받아서 read_line으로 받은 뒤 unwrap()으로 푼다.
### 여러 줄 입력
```rust
use::std::io::{self, Read};

fn main() {
    let mut input = String::new();
    io::stdin().read_line(&mut input).unwrap();

    let n = input.trim().parse::<usize>().unwrap();

    for _ in 0..n {
        input.clear();
        io::stdin().read_line(&mut input).unwrap();

    }

}
```
처음에는 몇 개의 줄을 입력받을 것인지 숫자를 입력하고, 반복문으로 그 숫자만큼 줄을 입력받는 방식으로 구현했다.
### 여러 숫자 입력
```rust
use std::io::{stdin, Read};

fn main() {
    let mut input = String::new();
    stdin().read_line(&mut input).unwrap();
    let mut input = input.split_ascii_whitespace().flat_map(str::parse::<usize>);

    let n = input.next().unwrap();


}
```
숫자를 공백 단위(1 3 4 5 6...)과 같이 입력받았을 때 사용하는 방식이다. 여기서 usize로 파싱하는 부분만 빠지면 문자열을 공백으로 입력받을 수도 있다.

## 출력
### 한 줄 출력
```rust
fn main() {
  let x = 3;
  println!("{x}");
}
```
