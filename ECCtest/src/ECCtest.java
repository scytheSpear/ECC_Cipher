import java.io.*;
import java.math.*;
import java.util.StringTokenizer;
import java.util.Random;
import java.util.Scanner;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.MessageDigest;

public class ECCtest {

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
   static Point G  = new Point(C.x, C.y);
          
public static void main(String[] args) throws Exception, IOException {
	  
	Function f = new Function();

	//Take input and encoding to a Point array Ma[] 
	Scanner in = new Scanner(System.in);
	
	String mes1 = "";
	char[] Mes;
	Point[] Ma;
	Point[] Ca;
	BigInteger As;
	BigInteger Bs;
	
	System.out.println("input a string");
	mes1 = in.nextLine();
	//System.out.println("input key As and Bs");
	//As = in.nextBigInteger();
	//Bs = in.nextBigInteger();
	As = f.RandomNum();
	Bs = f.RandomNum();
	
	Point Bp = G.multiply(Bs);
	Point Ap = G.multiply(As);
	
	Mes =new char[mes1.length()];
	Ca= new Point[mes1.length()];

	Point C1 = f.encryptASG(As, Bp);
	System.out.println("C1 y: " + C1.y);
	System.out.println("Randomtest As: "+ As + "Bs :" + Bs);
	
	
	for(int i = 0; i < mes1.length() ; i++ )
	{
		
		Mes[i] = mes1.charAt(i);
		
		
		System.out.println( "Message char Array: "+ Mes[i]);	
		//System.out.println(Encoding (Mes[i], C));

		//Take public key of B point Bp and private key of A big int As as input and encrpt message to point array Ma
		Ma = new Point[mes1.length()];
		Ma[i] = f.Encoding(Mes[i],C);
		
		if (f.PointOnCurve(Ma[i],C))
		{
		System.out.println("MArray y: " + Ma[i].y);
		
		Point C2 = f.encryptBPM(Ma[i], As, Bp);
		
		System.out.println("C2 y: "+C2.y);
		
		Ca[i] = C2;
		
		System.out.println("C2Array y: "+Ca[i].y);
		}
		else
		{
			System.out.println("M is not on C");
		}
	}
		
	char[] msg = new char[Ca.length];
	Point[] Msg = new Point[Ca.length];
	int i=0;
	
	for(Point c : Ca)
	{
		Msg[i] = f.decryptM(Bs, C1 , c);
		msg[i] = f.Decoding(Msg[i], C);
		
		System.out.println("C2 y: " + c.y);
		System.out.println("Point M y: " + Msg[i].y);
		System.out.println("charArray: " + msg[i]);
		
		i++;
	}
		String Pm  = String.valueOf(msg);
		System.out.println("plaintext: "+Pm);
		
	
	
	System.out.println("input a string");
	mes1 = in.nextLine();
	
	Point s = f.signing("send" , As ); 
    
	System.out.println(s.x);
	System.out.println(s.y);
	
	boolean x = f.verifying (s, Ap ,mes1);
	System.out.println(x);
	
	
	}
}


