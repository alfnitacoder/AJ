// fib.aj - Fibonacci numbers in AJLang

let n = 1
let a = 0
let b = 1

while n <= 10 do
  print a
  let t = a + b
  let a = b
  let b = t
  let n = n + 1
end

print "Done!"
