import java.io.Serializable;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Random;


public class Function implements Serializable{
	
	
	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	static final BigInteger Zero = new BigInteger("0");
	static final BigInteger One = new BigInteger("1");
	static final BigInteger MinusOne = new BigInteger("-1");

	static final int MAX_BUFFER_SIZE = 2048;
	static final int MAX_KEY_SIZE = 160;
	static final int MAX_ASCII = 255;
	
   static Curve C = Curve.curve;
   static BigInteger p = C.p;
   static BigInteger A = C.A;
   static BigInteger B = C.B;
   static BigInteger q = C.q;
   static BigInteger h = C.h;
   static Point G  = new Point(C.x,C.y);
   
   public BigInteger RandomNum()
   {
   	Random r = new Random();
   	BigInteger K = new BigInteger(MAX_KEY_SIZE, r);
           return K;
   }
   
   
   
   public BigInteger RandomR()
   {
	   	Random r = new Random();
	   	BigInteger R = new BigInteger(q.bitLength(), r);
	           return R;
   }



public Point encryptASG(BigInteger As, Point Bp)
{	
	Point C1 = G.multiply(As);

	return C1;
	
	}

public Point encryptBPM(Point M, BigInteger As, Point Bp)
{
	Point C2 =new Point(BigInteger.ZERO, BigInteger.ZERO);
	Point c2 = Bp.multiply(As);
	
	if (c2.y == M.y && c2.x == M.x)
	{
		C2= M.twice();
	}
	else
	{
		C2 = (c2.add(M));
	}
	return C2;	
}

public Point decryptM(BigInteger Bs, Point C1,Point C2) 
{
	Point M = C2.subtract(C1.multiply(Bs));
	return M;
	}

public Point signing(String M, BigInteger As )
{
    Function f = new Function();
	
    Point V = new Point (BigInteger.valueOf(0), BigInteger.valueOf(0));
	BigInteger v = BigInteger.valueOf(0);
	BigInteger x1 = BigInteger.valueOf(0);
	//BigInteger y1 = BigInteger.valueOf(0);
	BigInteger y2 = BigInteger.valueOf(0);

	do {
		v = f.RandomR();
		//v = BigInteger.valueOf(5);
		V = G.multiply(v);
		
	System.out.println("v :" + v);
    System.out.println("s :" + v.compareTo(q));
    System.out.println("Vx :" + V.x);	
    System.out.println("Vy :" + V.y);	
        
	//Hash message M to m
        
	byte[] bytesOfMessage = M.getBytes();
	
	MessageDigest md = null;
	try {
		md = MessageDigest.getInstance("MD5");
	} catch (NoSuchAlgorithmException e) {
		// TODO Auto-generated catch block
		e.printStackTrace();
	}
	byte[] m = md.digest(bytesOfMessage);
	
	//get bi as biginteger value of m
	BigInteger bi = new BigInteger(m);
	//BigInteger bi = BigInteger.valueOf(4);
	
	System.out.println("m :" + bi);
	
	
	 x1 = V.x.mod(q);
	 System.out.println("Vx :" + V.x);
	 System.out.println("x1 :" + x1);
	 
	 //y1 = ((bi.add(x1.multiply(As))).divide(v)).mod(q);
	 y2 = ((bi.add(x1.multiply(As)).mod(q)).multiply(v.modPow(MinusOne,q))).mod(q);
	 //System.out.println("Y1 :" + y1);
	 System.out.println("y2 :" + y2);
	 
	 
	}
	while ( V.x == BigInteger.valueOf(0) || y2 == BigInteger.valueOf(0) );
	
	Point S = new Point(x1 , y2);
		
	System.out.println(x1);
	System.out.println(y2);

	return S;
}

public boolean verifying (Point S, Point Ap, String M)
{
	boolean ver = false; 
	
	if (S.x.compareTo(q) + S.y.compareTo(q) > -2 || S.x.compareTo(BigInteger.valueOf(0)) + S.y.compareTo(BigInteger.valueOf(0)) < 2) 
	{
		ver = false;
	}
	else
	{
		BigInteger w = S.y.modPow(MinusOne, q);
		byte[] bytesOfMessage = M.getBytes();
		
		MessageDigest md = null;
		try {
			md = MessageDigest.getInstance("MD5");
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		byte[] m = md.digest(bytesOfMessage);
		//get bi as biginteger value of m
		BigInteger bi = new BigInteger(m);
		//BigInteger bi = BigInteger.valueOf(4);
        System.out.println("m :" + bi);
		
		BigInteger u1 = bi.multiply(w).mod(q);
		BigInteger u2 = S.x.multiply(w).mod(q);
                
		System.out.println("u1 :" + u1);
		System.out.println("u2 :" + u2);
		
		Point U1 = G.multiply(u1);
		System.out.println("u1x :" + U1.x);
		System.out.println("u1y :" + U1.y);
		Point U2 = Ap.multiply(u2);
		System.out.println("u2x :" + U2.x);
		System.out.println("u2y :" + U2.y);
		                        
		Point U = U1.add(U2);
		System.out.println("Ux :" + U.x);
		System.out.println("Ux :" +U.y);
		if (U.x.mod(q).equals(S.x))
		{
			ver = true;
			}
		else
			ver = false;
	}
	
	return ver;
}





public Point Encoding (char mes, Curve C )
{
	int m1 = (int) mes;
	
	BigInteger m = BigInteger.valueOf(m1);
	
	Point M = G.multiply(m);

	return M;
}


public char Decoding (Point M, Curve C )
{
	int ms = 0;
	BigInteger m = BigInteger.valueOf(1);
	
	//Point M1 = G.multiply(m);
			
	int i = 1;
	
		while ( (G.multiply(m).x.toString()).compareTo(M.x.toString()) != 0 && (G.multiply(m).y.toString()).compareTo(M.y.toString())!= 0)
		{

			m = BigInteger.valueOf(i);
			i ++ ;
		}
	
	//catch(Exception e){
		//System.err.println(e);
	//}

		ms = m.intValue();
	char mes = (char) ms;
	
	return mes;
	
}





public boolean PointOnCurve (Point P, Curve C) {
  try {
      BigInteger x1,y1, tmp;
      x1= BigInteger.ZERO;     
      y1= BigInteger.ZERO;     
      tmp= BigInteger.ZERO;     
      x1=x1.add(P.x);
      x1=x1.multiply(P.x);
      x1=x1.multiply(P.x);
      tmp = tmp.add(C.A);
      tmp = tmp.multiply(P.x);
      x1=x1.add(tmp);

      x1=x1.add(C.B);
      x1=x1.mod(C.p);

      y1=y1.add(P.y);
      y1=y1.multiply(P.y);
      y1=y1.mod(C.p);
      if (x1.compareTo(y1) == 0) return true;
      else
         return false;
   } catch (Exception e) {
     return false;
   }
 }

}
