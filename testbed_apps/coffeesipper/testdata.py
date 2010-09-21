import time
import random

def test_msgs():
    msgs = [ [ "jookos", "hello everyone!", time.time()],
             [ "jukka", "heeeee", time.time()-123],
             [ "janne", "font description using 'font'; you can u", time.time()-3600],
             [ "jookos", "specification such as '#00FF00' or a color name such as 'red'", time.time()-6000],
             [ "pekka", "rise", time.time()-10900],
             [ None, "something waacky .. ", time.time()-10],
             [ "mikko", "Vertical displacement, in 10000ths of an em. Can be negativ", time.time()-123123123],
             [ None, "something else waacky .. ", time.time()-1231232333],
             [ "juusef", "trikethrough lines; ", time.time()-12313344444],
             [ "jookos", "fallback will be done to other font", time.time()-1241244],
             [ "adsfaf", "ch as '#00FF00' or a color name ", time.time()-4444444],
             [ "janne", "lt. Most applications should no", time.time()-(3600*24*3)],
             [ "fsdf", "d', 'normal', 'semiexpanded', 'expande", time.time()-(3600*24)],
             [ "sfdf", "r 'false' whether to enable enable fallback. If enable fallback. If enable fallback. If enable fallback. Iffallback. If disabled, then characters wille' whether to enable fallback. If di e' whether to enable fallback. If di", time.time()],
             [ "sdf", "fallback will be done to other font", time.time()],
             [ "adsfaf", "ch as '#00FF00' or a color name ", time.time()],
             [ "janne", "font description using 'font'; you can u", time.time()],
             [ None, "and stuff .. ", time.time()],
             [ "jookos", "specification such as '#00FF00' or a color name such as 'red'", time.time()],
             [ "pekka", "rise", time.time()],
             [ "mikko", "Vertical displacement, in 10000ths of an em. Can be negativ", time.time()],
             [ "jookos", "specification such as '#00FF00' or a color name such as 'red'", time.time()],
             [ "pekka", "rise", time.time()],
             [ "mikko", "Vertical displacement, in 10000ths of an em. Can be negativ", time.time()],
             [ "jookos", "specification such as '#00FF00' or a color name such as 'red'", time.time()],
             [ "pekka", "rise", time.time()],
             [ "mikko", "Vertical displacement, in 10000ths of an em. Can be negativ", time.time()],
             [ "jookos", "specification such as '#00FF00' or a color name such as 'red'", time.time()],
             [ "pekka", "rise", time.time()],
             [ "mikko", "Vertical displacement, in 10000ths of an em. Can be negativ", time.time()],
             [ "juusef", "trikethrough lines; ", time.time()],
             [ "sd", "lt. Most applications should no", time.time()],
             [ "sd", "lt. Most applications should no", time.time()],
             [ "sd", "lt. Most applications should no", time.time()],
             [ "sd", "lt. Most applications should no", time.time()],
             [ "sdfsff", "uage code, indicating the text language", time.time()] ]
    t = time.time()
    for i in msgs:
        t -= random.randint(0, 3600*12)
        i[2] = t
    return msgs

