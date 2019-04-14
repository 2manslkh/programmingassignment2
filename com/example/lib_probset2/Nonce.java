package com.example.lib_probset2;

import java.util.Random;

public class Nonce {
    public static void main(String[] args) {
        System.out.println(getInt());
    }
    public static int getInt(){
        Random random = new Random();
        return Math.abs(random.nextInt());
    }

}
