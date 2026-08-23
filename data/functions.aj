// functions.aj - user-defined functions in AJLang

def greet(name)
  print "Hello, " + name + "!"
end

def add(a, b)
  return a + b
end

def factorial(n)
  if n <= 1 then
    return 1
  end
  return n * factorial(n - 1)
end

greet("AJLang")
print add(3, 7)
print "5! = " + factorial(5)
