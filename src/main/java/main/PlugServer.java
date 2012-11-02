package main;

import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Start a server, attach a client, and send a message.
 */
public class PlugServer implements Runnable {
  AtomicBoolean stop;
  
  public PlugServer(AtomicBoolean stop) {
    this.stop = stop;
  }
  
  public void run() {
    
    System.out.println("Starting server");
    
    ServerImpl server = new ServerImpl();
    
    try {
      server.startServer(50228);
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
    while (!stop.get())
      try {
        Thread.sleep(1000);
      } catch (InterruptedException e) {
        break;
      }
    
    server.close();
    return;
  }
  
  public static void run(String[] args) {
    new PlugServer(new AtomicBoolean(false)).run();
  }
}
