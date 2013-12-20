package com.examples.EC;

/**
 *　楕円曲線を用いたディジタル署名プログラム
 */


 // java.security セキュリティーフレームワークのクラスとインタフェースを提供
import java.security.KeyPair; //鍵ペア (公開鍵と非公開鍵) の単純なホルダー
import java.security.KeyPairGenerator;  //指定のアルゴリズムの公開鍵と非公開鍵のペアを生成
import java.security.PrivateKey;//非公開鍵クラス
import java.security.Provider;
import java.security.PublicKey;//公開鍵クラス
import java.security.SecureRandom;//暗号用に強化された乱数ジェネレータクラス
import java.security.Security;
import java.security.Signature;//デジタル署名アルゴリズムの機能提供クラス

import java.security.SignatureException;//以下3つは、例外処理クラス
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

public class EC {
	public static void main(String[] args) {
		System.out.println("start");

		//送信メッセージ 今回は暗号化してない文章をおくる
		byte[] message = "YOUR TIME IS LIMITED,SO DON’T WASTE IT LIVING SOMEONE ELSE’S LIFE."
				.getBytes();
		System.out.println("送信メッセージ："+new String(message));
		byte[] sign = null;

		
		//i 鍵の作成
		KeyPairGenerator keyPairGenerator = null;//ジェネレーターの初期化
		long generateKeyPairStartTime; //開始時間変数
		long generateKeyPairEndTime; //終了時間変数

		try {
			//指定のアルゴリズムの公開鍵と非公開鍵のペアを生成する KeyPairGenerator オブジェクトを返します。

			//ここでは、EC(Elliptic Curve)を選択
			keyPairGenerator = KeyPairGenerator.getInstance("EC");

		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
			return;
		}

		//使用できる(マシンに登録されている)セキュリティプロバイダを表示
		System.out.println("使用できるセキュリティプロバイダ");
		Provider p[] = Security.getProviders();
		for(Provider c : p){
			System.out.println(c);
		}

		/**
		 * SecureRandom()
		 * 最優先の Provider から順に、登録済みのセキュリティー Provider のリストをトラバースします。
		 * SecureRandom (RNG) アルゴリズムをサポートする最初の Provider の SecureRandomSpi 実装を
		 * カプセル化する新しい SecureRandom オブジェクトが返されます。RNG アルゴリズムをサポートする
		 *  Provider が存在しない場合、実装固有のデフォルト値が返されます。
		 */
		SecureRandom secureRandom = new SecureRandom();

		/**
		 * アルゴリズムの初期化
		 * 任意の鍵のサイズに対する鍵ペアジェネレータを初期化します。 デフォルトのパラメータセットと、
		 * 乱数発生の元として、もっとも高い優先順位でインストールされているプロバイダの SecureRandom 
		 * の実装を使用します。SecureRandom を提供するプロバイダが 1 つもインストールされていない場合は、
		 * システムが提供する乱数発生の元が使用されます。
		 */
		keyPairGenerator.initialize(256, secureRandom);//鍵長=256ビット


		generateKeyPairStartTime = System.nanoTime();//計測開始
		KeyPair keyPair = keyPairGenerator.generateKeyPair();//鍵ペアの作成
		generateKeyPairEndTime = System.nanoTime();//計測終了


		PrivateKey privateKey = keyPair.getPrivate();//非公開鍵
		PublicKey publicKey = keyPair.getPublic();//公開鍵



		//ii デジタル署名作成(本来は送信者が行う)
		Signature signatureSign = null;
		long signStartTime = 0;//認証開始時間
		long signEndTime = 0;//認証終了時間
		try {
			//普通のECDSA(Elliptic Curve Digital Signature Algorithm)を使う
			signatureSign = Signature.getInstance("NONEwithECDSA");
			signatureSign.initSign(privateKey, secureRandom);//iii 署名用に初期化
			signatureSign.update(message);

			signStartTime = System.nanoTime();
			sign = signatureSign.sign();//署名操作の結果の署名バイトを取得
			signEndTime = System.nanoTime();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
			return;
		} catch (InvalidKeyException e) {
			e.printStackTrace();
			return;
		} catch (SignatureException e) {
			e.printStackTrace();
			return;
		}
		
		
		
		//iv 本来はここで、通信を行なう
		
		
		
		//署名の検証(本来はメッセージ受信者が行う)
		Signature signatureVerify = null;
		boolean verifyResult;//検証結果
		long verifyStart;//検証開始時間
		long verifyEnd;//検証終了時間
		
		try {
			//署名が作成された普通のECDSA(Elliptic Curve Digital Signature Algorithm)を使う
			signatureVerify = Signature.getInstance("NONEwithECDSA");
			signatureVerify.initVerify(publicKey);//vi
			signatureVerify.update(message);//v

			verifyStart = System.nanoTime();//検証開始
			verifyResult = signatureVerify.verify(sign);//vii
			verifyEnd = System.nanoTime();//検証終了

			if (verifyResult) {//メッセージが改竄されてないか
				System.out.print("OK");
				System.out.println("\t");
			} else {
				System.out.print("NG");
				System.out.println("\t");
			}
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
			return;
		} catch (InvalidKeyException e) {
			e.printStackTrace();
			return;
		} catch (SignatureException e) {
			e.printStackTrace();
			return;
		}

		System.out.print("鍵作成時間(ns)："+(generateKeyPairEndTime - generateKeyPairStartTime));
		System.out.print("\t  ");
		System.out.print("認証時間(ns)："+(signEndTime - signStartTime));
		System.out.print("\t  ");
		System.out.print("認証確認時間(ns)："+(verifyEnd - verifyStart));
		System.out.println();
	}
}

