package com.junsang.config.config;

import com.ulisesbocchio.jasyptspringboot.annotation.EnableEncryptableProperties;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.config.server.EnableConfigServer;
import org.springframework.context.annotation.Bean;

import java.io.File;
import java.io.FileReader;

@SpringBootApplication
@EnableConfigServer
@EnableEncryptableProperties
public class ConfigApplication {

	public static void main(String[] args) {
		SpringApplication.run(ConfigApplication.class, args);
	}

	/**
	 * jasypt 라이브러리 복호화를 위한 Secret-key 초기화
	 *
	 * 아래 값을 복호화하기 위해 사용
	 * - github URL
	 * - github id
	 * - github password
	 */
	@Bean
	public static void secretKeyInit() {

		// 로컬 파일 읽기
		File filePath = new File("D:\\toyProject-secret-key.txt");

		// 입력 스트림
		FileReader filereader = null;

		// 암호화(jasypt)된 값을 복호화 하기 위한 Secret-key
		String secretKey = "";
		try {
			filereader = new FileReader(filePath);
			int singleCh = 0;
			while((singleCh = filereader.read()) != -1){
				secretKey += (char) singleCh;
			}
			filereader.close();
		} catch (Exception e) {
			e.printStackTrace();
		}

		// Secret-key 주입
		System.setProperty("jasypt.encryptor.password", secretKey);
	}

}
