package com.projetmessagerie.vertimail;

import io.vertx.core.AbstractVerticle;
import io.vertx.core.Future;
import io.vertx.core.Promise;
import io.vertx.core.Vertx;
import io.vertx.core.buffer.Buffer;
import io.vertx.core.datagram.DatagramSocket;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.web.Router;
import io.vertx.ext.web.handler.BodyHandler;
import io.vertx.ext.web.templ.pebble.PebbleTemplateEngine;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class MainVerticle extends AbstractVerticle {

  PebbleTemplateEngine engine;
  Map<String, Integer> ipCounts = new HashMap<>();

  @Override
  public void start(Promise<Void> startPromise) throws Exception {

    engine = PebbleTemplateEngine.create(vertx);
    Router router = Router.router(vertx);
    router.route().handler(BodyHandler.create());

    // --- ROUTE CSS (Indispensable pour le design) ---
    router.get("/style.css").handler(ctx -> {
      // Essaie de lire le fichier dans les ressources
      vertx.fileSystem().readFile("src/main/resources/style.css")
        .onSuccess(buffer -> ctx.response().putHeader("content-type", "text/css").end(buffer))
        .onFailure(err -> ctx.response().sendFile("style.css")); // Fallback
    });

    // --- ROUTES WEB ---

    router.get("/").handler(ctx -> {
      engine.render(ctx.data(), "templates/login.peb")
        .onSuccess(buffer -> ctx.response().putHeader("content-type", "text/html").end(buffer));
    });

    router.get("/register").handler(ctx -> {
      engine.render(ctx.data(), "templates/register.peb")
        .onSuccess(buffer -> ctx.response().putHeader("content-type", "text/html").end(buffer));
    });

    router.post("/register").handler(ctx -> {
      String username = ctx.request().getFormAttribute("username");
      String password = ctx.request().getFormAttribute("password");
      if (username == null || username.trim().isEmpty() || password == null) {
        ctx.response().end("Erreur : Pseudo ou mot de passe vide.");
        return;
      }
      String base = "storage/" + username;
      vertx.fileSystem().exists(base).onSuccess(exists -> {
        if (exists) {
          ctx.response().end("Erreur : Pseudo pris !");
        } else {
          vertx.fileSystem().mkdirs(base + "/inbox").onSuccess(v -> {
            vertx.fileSystem().mkdirs(base + "/outbox");
            vertx.fileSystem().mkdirs(base + "/draft");
            vertx.fileSystem().mkdirs(base + "/trash");
            String hash = hashPassword(password);
            vertx.fileSystem().writeFile(base + "/password.hash", Buffer.buffer(hash))
              .onSuccess(vv -> ctx.response().putHeader("content-type", "text/html").end("<h1>Compte cree !</h1><a href='/'>Connexion</a>"));
          });
        }
      });
    });

    router.post("/login").handler(ctx -> {
      String username = ctx.request().getFormAttribute("username");
      String password = ctx.request().getFormAttribute("password");
      String hashPath = "storage/" + username + "/password.hash";

      vertx.fileSystem().exists(hashPath).onSuccess(exists -> {
        if (!exists) {
          ctx.put("error", "Compte inexistant.");
          engine.render(ctx.data(), "templates/login.peb").onSuccess(buf -> ctx.response().end(buf));
        } else {
          vertx.fileSystem().readFile(hashPath).onSuccess(buffer -> {
            if (buffer.toString().equals(hashPassword(password))) {
              ctx.redirect("/box?username=" + username + "&folder=inbox");
            } else {
              ctx.put("error", "Mot de passe faux.");
              engine.render(ctx.data(), "templates/login.peb").onSuccess(buf -> ctx.response().end(buf));
            }
          });
        }
      });
    });

    router.get("/compose").handler(ctx -> {
      String user = ctx.request().getParam("user");
      ctx.put("username", user);
      engine.render(ctx.data(), "templates/compose.peb").onSuccess(buf -> ctx.response().end(buf));
    });

    router.post("/send").handler(ctx -> {
      String sender = ctx.request().getFormAttribute("sender");
      String recipient = ctx.request().getFormAttribute("recipient");
      String subject = ctx.request().getFormAttribute("subject");
      String content = ctx.request().getFormAttribute("content");
      JsonObject mail = new JsonObject().put("from", sender).put("to", recipient)
        .put("date", java.time.Instant.now().toString()).put("subject", subject).put("content", content);
      String filename = System.currentTimeMillis() + ".json";
      vertx.fileSystem().writeFile("storage/" + recipient + "/inbox/" + filename, mail.toBuffer())
        .onSuccess(v -> vertx.fileSystem().writeFile("storage/" + sender + "/outbox/" + filename, mail.toBuffer())
          .onSuccess(v2 -> ctx.redirect("/box?username=" + sender + "&folder=outbox"))
          .onFailure(e -> ctx.response().end("Erreur outbox")))
        .onFailure(e -> ctx.response().end("Erreur destinataire"));
    });

    router.post("/draft").handler(ctx -> {
      String sender = ctx.request().getFormAttribute("sender");
      String content = ctx.request().getFormAttribute("content");
      String recipient = ctx.request().getFormAttribute("recipient");
      String subject = ctx.request().getFormAttribute("subject");
      JsonObject mail = new JsonObject().put("from", sender).put("to", recipient == null ? "" : recipient)
        .put("date", java.time.Instant.now().toString()).put("subject", subject).put("content", content);
      vertx.fileSystem().writeFile("storage/" + sender + "/draft/" + System.currentTimeMillis() + ".json", mail.toBuffer())
        .onSuccess(v -> ctx.redirect("/box?username=" + sender + "&folder=draft"));
    });

    router.post("/delete").handler(ctx -> {
      String username = ctx.request().getFormAttribute("username");
      String folder = ctx.request().getFormAttribute("folder");
      String filename = ctx.request().getFormAttribute("filename");
      String path = "storage/" + username + "/" + folder + "/" + filename;
      if ("trash".equals(folder)) vertx.fileSystem().delete(path).onSuccess(v -> ctx.redirect("/box?username=" + username + "&folder=" + folder));
      else vertx.fileSystem().move(path, "storage/" + username + "/trash/" + filename).onSuccess(v -> ctx.redirect("/box?username=" + username + "&folder=" + folder));
    });

    router.get("/read").handler(ctx -> {
      String username = ctx.request().getParam("username");
      String folder = ctx.request().getParam("folder");
      String id = ctx.request().getParam("id");
      vertx.fileSystem().readFile("storage/" + username + "/" + folder + "/" + id)
        .onSuccess(buffer -> {
          ctx.put("username", username).put("folder", folder).put("id", id).put("mail", new JsonObject(buffer));
          engine.render(ctx.data(), "templates/read.peb").onSuccess(buf -> ctx.response().end(buf));
        });
    });

    router.get("/box").handler(ctx -> {
      String username = ctx.request().getParam("username");
      String folder = ctx.request().getParam("folder") == null ? "inbox" : ctx.request().getParam("folder");
      String folderPath = "storage/" + username + "/" + folder;
      final String currentFolder = folder;
      vertx.fileSystem().readDir(folderPath).onSuccess(files -> {
        List<JsonObject> mails = new ArrayList<>();
        Future<Void> chain = Future.succeededFuture();
        for (String path : files) {
          chain = chain.compose(v -> vertx.fileSystem().readFile(path).map(buf -> {
            JsonObject json = new JsonObject(buf);
            json.put("id", new File(path).getName());
            mails.add(json);
            return null;
          }));
        }
        chain.onSuccess(v -> {
          ctx.put("username", username).put("mails", mails).put("folder", currentFolder);
          engine.render(ctx.data(), "templates/inbox.peb").onSuccess(buf -> ctx.response().end(buf));
        });
      }).onFailure(e -> {
        ctx.put("username", username).put("mails", new ArrayList<>()).put("folder", currentFolder);
        engine.render(ctx.data(), "templates/inbox.peb").onSuccess(buf -> ctx.response().end(buf));
      });
    });

    // ================================================================
    // --- API MOBILE (Pour l'application Android en mode connecté) ---
    // ================================================================

    // 1. Vérifier le mot de passe (Login)
    router.post("/api/login").handler(ctx -> {
      String username = ctx.request().getFormAttribute("username");
      String password = ctx.request().getFormAttribute("password");
      String hashPath = "storage/" + username + "/password.hash";

      vertx.fileSystem().exists(hashPath).onSuccess(exists -> {
        if (!exists) {
          ctx.json(new JsonObject().put("status", "error").put("message", "Utilisateur inconnu"));
        } else {
          vertx.fileSystem().readFile(hashPath).onSuccess(buffer -> {
            if (buffer.toString().equals(hashPassword(password))) {
              // C'est gagné !
              ctx.json(new JsonObject().put("status", "ok").put("username", username));
            } else {
              ctx.json(new JsonObject().put("status", "error").put("message", "Mauvais mot de passe"));
            }
          });
        }
      });
    });

    // 2. Envoyer un mail authentifié (HTTP)
    router.post("/api/send").handler(ctx -> {
      String sender = ctx.request().getFormAttribute("sender");
      String recipient = ctx.request().getFormAttribute("recipient");
      String subject = ctx.request().getFormAttribute("subject");
      String content = ctx.request().getFormAttribute("content");

      // On vérifie que le destinataire existe
      vertx.fileSystem().exists("storage/" + recipient).onSuccess(exists -> {
        if (exists) {
          JsonObject mail = new JsonObject()
            .put("from", sender) // Cette fois, c'est le vrai pseudo !
            .put("to", recipient)
            .put("date", java.time.Instant.now().toString())
            .put("subject", subject)
            .put("content", content);

          String filename = System.currentTimeMillis() + ".json";

          // On écrit chez le destinataire ET l'expéditeur
          vertx.fileSystem().writeFile("storage/" + recipient + "/inbox/" + filename, mail.toBuffer())
            .onSuccess(v -> {
              vertx.fileSystem().writeFile("storage/" + sender + "/outbox/" + filename, mail.toBuffer());
              ctx.json(new JsonObject().put("status", "ok"));
            });
        } else {
          ctx.json(new JsonObject().put("status", "error").put("message", "Destinataire introuvable"));
        }
      });
    });

    // --- SERVEUR UDP ---
    DatagramSocket socket = vertx.createDatagramSocket();
    socket.listen(9999, "0.0.0.0").onSuccess(so -> {
      System.out.println("👻 Serveur UDP anonyme écoute sur le port 9999");
      socket.handler(packet -> {
        String ip = packet.sender().host();
        int port = packet.sender().port();

        int currentCount = ipCounts.getOrDefault(ip, 0);
        if (currentCount >= 10) {
          System.out.println("⛔ Spam bloqué depuis " + ip);
          socket.send(Buffer.buffer("Erreur : Limite de 10 messages par jour atteinte."), port, ip).onSuccess(v -> {}).onFailure(err -> {});
          return;
        }
        ipCounts.put(ip, currentCount + 1);

        String data = packet.data().toString();
        String[] lines = data.split("\n", 3);
        if (lines.length >= 3) {
          String recipient = lines[0].trim();
          String subject = lines[1].trim();
          String content = lines[2].trim();

          JsonObject mail = new JsonObject()
            .put("from", "Anonyme (" + ip + ":" + port + ")")
            .put("to", recipient)
            .put("date", java.time.Instant.now().toString())
            .put("subject", "[UDP] " + subject)
            .put("content", content);

          String filename = "udp_" + System.currentTimeMillis() + ".json";
          String path = "storage/" + recipient + "/inbox/" + filename;

          vertx.fileSystem().exists("storage/" + recipient + "/inbox").onSuccess(exists -> {
            if (exists) {
              vertx.fileSystem().writeFile(path, mail.toBuffer()).onSuccess(v -> {
                System.out.println("👻 Message UDP reçu pour " + recipient);
                socket.send(Buffer.buffer("Message bien recu par le serveur !"), port, ip).onSuccess(vv -> {}).onFailure(err -> {});
              });
            } else {
              socket.send(Buffer.buffer("Erreur : Destinataire inconnu."), port, ip).onSuccess(vv -> {}).onFailure(err -> {});
            }
          });
        }
      });
    });

    // --- NETTOYAGE AUTO ---
    // Pense à changer cette valeur pour le rendu final (30L * 24 * 60 * 60 * 1000L)
    long MAX_AGE = 30 * 1000L; // 30 secondes pour le test

    vertx.setPeriodic(10000, id -> {
      vertx.fileSystem().readDir("storage").onSuccess(users -> {
        for (String userPath : users) {
          String trashPath = userPath + "/trash";
          vertx.fileSystem().readDir(trashPath).onSuccess(files -> {
            for (String filePath : files) {
              vertx.fileSystem().props(filePath).onSuccess(props -> {
                long fileAge = System.currentTimeMillis() - props.lastModifiedTime();
                if (fileAge > MAX_AGE) {
                  vertx.fileSystem().delete(filePath).onSuccess(v -> {
                    System.out.println("🧹 Nettoyage auto : " + filePath + " supprimé.");
                  });
                }
              });
            }
          }).onFailure(err -> {});
        }
      }).onFailure(err -> {});
    });

    vertx.createHttpServer().requestHandler(router).listen(8888).onSuccess(s -> {
      startPromise.complete();
      System.out.println("✅ Serveur Web sécurisé : http://localhost:8888");
    });
  }

  private String hashPassword(String password) {
    try {
      MessageDigest digest = MessageDigest.getInstance("SHA-256");
      byte[] encodedhash = digest.digest(password.getBytes(StandardCharsets.UTF_8));
      StringBuilder hexString = new StringBuilder(2 * encodedhash.length);
      for (byte b : encodedhash) {
        String hex = Integer.toHexString(0xff & b);
        if (hex.length() == 1) hexString.append('0');
        hexString.append(hex);
      }
      return hexString.toString();
    } catch (Exception e) { throw new RuntimeException(e); }
  }

  public static void main(String[] args) {
    Vertx vertx = Vertx.vertx();
    vertx.deployVerticle(new MainVerticle());
  }
}
