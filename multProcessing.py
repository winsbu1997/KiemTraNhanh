from multiprocessing import Process, Manager

def f():
    for index in range(100):
        if(index % 2 == 0):
            print(index)

def g():
    for index in range(100):
        if(index % 2 != 0):
            print(index)

if __name__ == '__main__':
    print('nokiafsfe')
    p = Process(target=f)
    p.start()
    #p.join()
    for index in range(5):
        print("nokia" , str(index))
    t = Process(target= g)
    t.start()
    p.join()
    t.join()