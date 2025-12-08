package com.projetmessagerie.vertimail;

import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;

public class TestUDP {
  public static void main(String[] args) {
    try {

      String message = "mouloud\nLe Corbeau\nJe te vois... je sais que tu codes en Java !";

      // On prépare le paquet
      byte[] buffer = message.getBytes();
      InetAddress address = InetAddress.getByName("localhost");
      int port = 9999; // La fameuse fenêtre ouverte

      // On envoie !
      DatagramSocket socket = new DatagramSocket();
      DatagramPacket packet = new DatagramPacket(buffer, buffer.length, address, port);
      socket.send(packet);

      System.out.println("🥷 Message anonyme envoyé à mouloud !");

      // On regarde si le serveur répond
      byte[] bufferRecv = new byte[1024];
      DatagramPacket packetReceived = new DatagramPacket(bufferRecv, bufferRecv.length);
      socket.receive(packetReceived);
      System.out.println("Réponse du serveur : " + new String(packetReceived.getData()).trim());

      socket.close();
    } catch (Exception e) {
      e.printStackTrace();
    }
  }
}
