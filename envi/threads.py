'''
A couple useful thread related toys...
'''

import threading

def firethread(func):
    '''
    A decorator which fires a thread to do the given call.

    NOTE: This means these methods may not return anything
    and callers may not expect sync behavior!
    '''
    def dothread(*args, **kwargs):
        thr = threading.Thread(target=func, args=args, kwargs=kwargs)
        thr.setDaemon(True)
        thr.start()
    return dothread

