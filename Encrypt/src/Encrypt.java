import java.io.*;
import java.math.*;
import java.util.*;

public class Encrypt {

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
	
	String mes1 = "0";
	char[] Mes;
	Point[] Ma;
	Point[] Ca;
	BigInteger As;
	//BigInteger Bs;
	
	//System.out.println("input key As and Bs");
	//As = in.nextBigInteger();
	//Bs = in.nextBigInteger();
	//As = f.RandomNum();
	
	//Bs = f.RandomNum();
	
	Point Bp = new Point(BigInteger.ZERO,BigInteger.ZERO);
	
	System.out.println("Input sender privite key");
	As = in.nextBigInteger();

	Point Ap = G.multiply(As);
	System.out.println("Apub x :" + Ap.x);
	System.out.println("Apub y :" + Ap.y);

	//System.out.println("Randomtest As: "+ As);
		
	System.out.println("Input recipient Public key Bp.x and Bp.y");
	System.out.println("Enter Bp.x");
	Bp.x = in.nextBigInteger();
	System.out.println("Enter Bp.y");
	Bp.y = in.nextBigInteger();
	Bp = new Point(Bp.x , Bp.y);
	
	
	System.out.println("input a string");
	mes1 = in.next();
	
	Mes =new char[mes1.length()];
	Ca= new Point[mes1.length()+2];

	Point C1 = f.encryptASG(As);
	Ca[0] = C1;
	//System.out.println("C1 y: " + C1.y);
	
	System.out.println("input username");
	String username = in.next();
	Ca[1] = f.signing(username , As ); 
	
	
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
		
		//System.out.println("C2 y: "+C2.y);
		
		Ca[i+2] = C2;
		System.out.println("C2Array y: "+Ca[i+2].y);
		}
		else
		{
			System.out.println("M is not on C");
		}
		
		FileOutputStream fout = new FileOutputStream("E:\\point.ser");
		ObjectOutputStream oos = new ObjectOutputStream(fout);
		oos.writeObject(Ca);
		
	}
	
	
	
	/*
	FileInputStream fin = new FileInputStream("F:\\point.ser");
	ObjectInputStream ois = new ObjectInputStream(fin);
	Point Preadfile[] = (Point[]) ois.readObject();
	
	char[] msg = new char[Preadfile.length];
	Point[] Msg = new Point[Preadfile.length];
	int i=0;
	
	for(Point c : Msg)
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
		
	
	/*
	Point s = f.signing(mes1 , As ); 
	
	boolean x = f.verifying (s, Ap ,mes1);
	System.out.println(x);
	*/
	
	}
}


