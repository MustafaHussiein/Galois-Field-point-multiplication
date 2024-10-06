import hashlib
from hashlib import sha256
from math import sqrt
import base64
import cv2
import time

start = time.time()
n =  1569275433846670190958947355803350458831205595451630533029
k = 1542725565216523985789236956265265265235675811949404040041
priv_key = 1275552191113212300012030439187146164646146646466749494799
pub_key_x = int("045DE37E756BD55D72E3768CB396FFEB962614DEA4CE28A2E", 16)  
pub_key_y = int("755C0E0E02F5FB132CAF416EF85B229BBB8E1352003125BA1", 16)
kB_x = int("438E5A11FB55E4C65471DCD49E266142A3BDF2BF9D5772D5", 16)
kB_y = int("2AD603A05BD1D177649F9167E6F475B7E2FF590C85AF15DA", 16)
rlst = []
slst = []
Hlst = []
imglst = []
def multiplydPoints(x1,y1,x2,y2,c1,c2,c3,c4,c6,num):
    if x1 == x2 and y1 == y2:
        slope = (y2 - y1)/(x2 -x1)
        a = (slope*slope) + c1*slope - c2 -x1 -x2
        b = (-((c1*a) + c3) - sqrt((((c1*a) + c3)*((c1*a) + c3)) + 4*((a*a*a)+ c2*(a*a) +(c4*a) +c6)))/2
    else:
        b2 = (c1*c1) + (4*c2)
        b4 = (2*c4) + (c1*c3)
        b6 = (c3*c3) + (4*c6)
        b8 = (c1*c1*c6) + (4*c2*c6) - (c1*c3*c4) + (c2*c3*c3) - (c4*c4)
        a = ((x1*x1*x1*x1)-(b4*x1*x1)-(2*b6*x1)-b8)/((4*x*x*x)+(b2*x*x)+(4*b4*x)+b6)
        b = (-((c1*a) + c3) - sqrt((((c1*a) + c3)*((c1*a) + c3)) + 4*((a*a*a)+ c2*(a*a) +(c4*a) +c6)))/2 
    if num == 0 :
        return a,b
    else:
        num -=1
        multiplydPoints(x1,y1,a,b,c1,c2,c3,c4,c6,num)
def Sign():
    url = input("Enter the image url:")
    img = cv2.imread(url)
    imglst.append(img)
    with open(url, "rb") as image2string:
        converted_string = base64.b64encode(image2string.read())
        
    Hint = int(hashlib.sha1(str(converted_string).encode("utf-8")).hexdigest(), 16) #968236873715988614170569073515315707566766479517
    Hlst.append(Hint)
    print("Hash = "+str(Hint))
    print("Private key = "+str(priv_key))
    print("Public key = "+str(pub_key_x)+","+str(pub_key_y))
    r = kB_x%n
    rlst.append(r)
    s = ((modinv(k,n))*(Hint+(priv_key*r)))%n
    slst.append(s)
    print("The signature is: r = "+str(r)+", s = "+str(s))
    
def verify():
    imgname = input("Enter msg url:")
    img = cv2.imread(imgname)
    with open(imgname, "rb") as image2string:
        converted_string = base64.b64encode(image2string.read())
    newhash = int(hashlib.sha1(str(converted_string).encode("utf-8")).hexdigest(), 16)
    """newhash = int(hashlib.sha1(str(converted_string).encode("utf-8")).hexdigest(), 16)
    T = modinv(slst[0],n)
    L = (newhash*T) %n
    Q = (rlst[0] * T) % n
    result = multiplydPoints(L) + Q * pk * op     
    r = result[0]%n
    r = int(r)
    if(r == rlst[0]):
        print("Signature is verified")
        cv2.imshow("image", imglst[0])
        cv2.waitKey(0)
        cv2.destroyAllWindows()"""
    r = kB_x%n
    r = int(r)
    #Hint = int(input("Enter the image hash:"))
    s = (((priv_key*r)+newhash)*(modinv(k,n)))%n
    if(r == rlst[0] and s == slst[0]):
        print("Signature is verified")
        cv2.imshow("image", imglst[0])
        cv2.waitKey(0)
        cv2.destroyAllWindows()
    else:
        print("Signature is not verified")
        #print(str(Hint),str(newhash))
        print("r:" + str(r), "Original r:"+ str(rlst[0]))
        print("S:" + str(s), "Original S:"+ str(slst[0]))

def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)

def modinv(a, m):
    g, x, y = egcd(a, m)
    if g != 1:
        raise Exception('modular inverse does not exist')
    else:
        return x % m
        
        
Sign()
end1 = time.time()
print(end1 - start)
start2 = time.time()
verify()
end2 = time.time()
print(end2 - start2)
