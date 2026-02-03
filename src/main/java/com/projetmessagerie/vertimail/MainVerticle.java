package com.projetmessagerie.vertimail;
import java.util.Collections;
import io.vertx.core.AbstractVerticle;
import io.vertx.core.Future;
import io.vertx.core.Promise;
import io.vertx.core.buffer.Buffer;
import io.vertx.core.datagram.DatagramSocket;
import io.vertx.core.file.CopyOptions;
import io.vertx.core.http.ServerWebSocket;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.web.FileUpload;
import io.vertx.ext.web.Router;
import io.vertx.ext.web.handler.BodyHandler;
import io.vertx.ext.web.handler.SessionHandler;
import io.vertx.ext.web.sstore.LocalSessionStore;
import io.vertx.ext.web.templ.pebble.PebbleTemplateEngine;

import java.awt.Graphics2D;
import java.awt.RenderingHints;
import java.awt.image.BufferedImage;
import java.io.File;
import java.io.FileInputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Pattern;
import javax.imageio.ImageIO;

public class MainVerticle extends AbstractVerticle {

  PebbleTemplateEngine engine;
  Map<String, Integer> ipCounts = new HashMap<>();

  // LISTE DES CONNEXIONS TEMPS RÉEL (WebSockets)
  Map<String, ServerWebSocket> activeSockets = new ConcurrentHashMap<>();

  // Mémoire tampon pour ne pas recalculer les photos tout le temps
  Map<String, String> avatarCache = new ConcurrentHashMap<>();

  // Regex pour la validation du mot de passe
  private static final Pattern PASSWORD_PATTERN =
    Pattern.compile("^(?=.*[0-9])(?=.*[a-z])(?=.*[A-Z])(?=.*[@#$%^&+=!])(?=\\S+$).{8,}$");

  private static final long SESSION_TIMEOUT_DEFAULT = 30 * 60 * 1000L; // 30 minutes

  @Override
  public void start(Promise<Void> startPromise) throws Exception {
    System.out.println("🚀 Démarrage de l'application...");

    engine = PebbleTemplateEngine.create(vertx);
    Router router = Router.router(vertx);

    // --- GESTIONNAIRE D'ERREURS GLOBAL (POUR LE DEBUG) ---
    router.route().failureHandler(ctx -> {
      System.err.println("🔥 ERREUR SERVEUR SUR " + ctx.request().path());
      if (ctx.failure() != null) {
        ctx.failure().printStackTrace();
      }
      ctx.response().setStatusCode(500).end("Erreur interne: " + (ctx.failure() != null ? ctx.failure().getMessage() : "Inconnue"));
    });

    // 1. Activer le BodyHandler (Gestion des uploads) - LIMITE AUGMENTÉE À 50 Mo
    router.route().handler(BodyHandler.create()
        .setUploadsDirectory("file-uploads")
        .setBodyLimit(50 * 1024 * 1024)); // 50 Mo max pour éviter les erreurs sur mobile

    // 2. Activer les Sessions
    SessionHandler sessionHandler = SessionHandler.create(LocalSessionStore.create(vertx))
      .setSessionTimeout(SESSION_TIMEOUT_DEFAULT);
    router.route().handler(sessionHandler);

    // Créer les dossiers de stockage
    vertx.fileSystem().mkdirs("storage/attachments");
    vertx.fileSystem().mkdirs("storage/avatars");

    // --- ROUTE CSS ---
    router.get("/style.css").handler(ctx -> {
      vertx.fileSystem().readFile("src/main/resources/style.css")
        .onSuccess(buffer -> ctx.response().putHeader("content-type", "text/css").end(buffer))
        .onFailure(err -> ctx.response().sendFile("style.css"));
    });

    // ============================================================
    // --- WEBSOCKETS : NOTIFICATIONS INSTANTANÉES ---
    // ============================================================
    router.route("/api/ws").handler(ctx -> {
      ctx.request().toWebSocket().onSuccess(ws -> {
        String user = ctx.request().getParam("username");
        if (user != null) {
          activeSockets.put(user, ws);
          System.out.println("🔌 Connecté (WS) : " + user);
          ws.closeHandler(v -> activeSockets.remove(user));
        } else {
          ws.close();
        }
      }).onFailure(err -> ctx.fail(400));
    });

    // --- ROUTE ADMIN POUR RESET (SYNTAXE VERT.X 5) ---
    router.get("/admin/nuke").handler(ctx -> {
      vertx.fileSystem().deleteRecursive("storage")
        .compose(v -> vertx.fileSystem().mkdirs("storage/attachments"))
        .compose(v -> vertx.fileSystem().mkdirs("storage/avatars"))
        .onSuccess(v -> {
          avatarCache.clear();
          ctx.session().destroy();
          ctx.response()
            .putHeader("content-type", "text/html; charset=utf-8")
            .end("<h1>💥 BOOM ! Tout est effacé.</h1><a href='/'>Retour accueil</a>");
        })
        .onFailure(err -> {
          // En cas d'erreur (ex: dossier déjà vide), on tente quand même de recréer la structure
          vertx.fileSystem().mkdirs("storage/attachments")
            .compose(vv -> vertx.fileSystem().mkdirs("storage/avatars"))
            .onComplete(res -> ctx.response().end("Nettoyage partiel ou dossier inexistant."));
        });
    });

    // --- ROUTES PUBLIQUES (LOGIN / REGISTER) ---

    router.get("/").handler(ctx -> {
      if (ctx.session().get("user") != null) {
        ctx.redirect("/box");
        return;
      }
      io.vertx.core.http.Cookie rememberCookie = ctx.request().getCookie("remember_user");
      if (rememberCookie != null) {
        String user = rememberCookie.getValue();
        ctx.session().put("user", user);
        ctx.redirect("/box");
        return;
      }
      String success = ctx.request().getParam("success");
      if ("created".equals(success)) {
        ctx.put("success", "Compte créé avec succès ! Connectez-vous.");
      } else if ("reset".equals(success)) {
        ctx.put("success", "Mot de passe réinitialisé avec succès !");
      }
      engine.render(ctx.data(), "templates/login.peb")
        .onSuccess(buffer -> ctx.response().putHeader("content-type", "text/html").end(buffer));
    });

    router.get("/register").handler(ctx -> {
      if (ctx.session().get("user") != null) {
        ctx.redirect("/box");
        return;
      }
      engine.render(ctx.data(), "templates/register.peb")
        .onSuccess(buffer -> ctx.response().putHeader("content-type", "text/html").end(buffer));
    });

    router.post("/register").handler(ctx -> {
      String username = ctx.request().getFormAttribute("username");
      String password = ctx.request().getFormAttribute("password");
      String confirmPassword = ctx.request().getFormAttribute("confirmPassword");
      List<FileUpload> uploads = ctx.fileUploads();

      if (username == null || username.trim().isEmpty() || password == null) {
        ctx.response().end("Erreur : Pseudo ou mot de passe vide.");
        return;
      }
      if (!password.equals(confirmPassword)) {
        ctx.response().end("Erreur : Les mots de passe ne correspondent pas.");
        return;
      }
      if (!PASSWORD_PATTERN.matcher(password).matches()) {
        ctx.response().end("Erreur : Mot de passe non conforme.");
        return;
      }

      String base = "storage/" + username;
      vertx.fileSystem().exists(base).onSuccess(exists -> {
        if (exists) {
          ctx.response().end("Erreur : Pseudo pris !");
        } else {
          vertx.fileSystem().mkdirs(base + "/inbox")
            .compose(v -> vertx.fileSystem().mkdirs(base + "/outbox"))
            .compose(v -> vertx.fileSystem().mkdirs(base + "/draft"))
            .compose(v -> vertx.fileSystem().mkdirs(base + "/trash"))
            .onSuccess(v -> {
              String hash = hashPassword(password);

              // CORRECTION : Attendre la fin du traitement de l'avatar
              Future<Void> avatarFuture = Future.succeededFuture();
              if (!uploads.isEmpty()) {
                FileUpload avatar = uploads.get(0);
                String avatarPath = "storage/avatars/" + username;
                avatarFuture = resizeAndSaveAvatar(avatar.uploadedFileName(), avatarPath);
              }

              avatarFuture.onComplete(res -> {
                  // On continue même si l'avatar échoue (on aura l'avatar par défaut)
                  vertx.fileSystem().writeFile(base + "/password.hash", Buffer.buffer(hash))
                    .onSuccess(vv -> ctx.redirect("/?success=created"));
              });
            });
        }
      });
    });

    // --- SERVIR L'AVATAR (Génération dynamique style Gmail / Mobile) ---
    router.get("/avatar/:username").handler(ctx -> {
      String username = ctx.request().getParam("username");
      String avatarPath = "storage/avatars/" + username;vertx.fileSystem().exists(avatarPath).onSuccess(exists -> {
        ctx.response().putHeader("Cache-Control", "no-cache");
        if (exists) {
          ctx.response().putHeader("Content-Type", "image/jpeg");
          ctx.response().sendFile(avatarPath);
        } else {
          // --- ON REPREND LES MÊMES COULEURS QUE SUR MOBILE ---
          String[] colors = {"#EF5350", "#EC407A", "#AB47BC", "#7E57C2", "#5C6BC0", "#42A5F5", "#26A69A", "#66BB6A", "#FFA726", "#795548"};
          int index = Math.abs(username.hashCode()) % colors.length;
          String color = colors[index];

          String initial = username.isEmpty() ? "?" : String.valueOf(username.charAt(0)).toUpperCase();

          // On génère un SVG avec la bonne couleur de fond
          String svg = "<svg xmlns='http://www.w3.org/2000/svg' width='100' height='100' viewBox='0 0 100 100'>" +
            "<rect width='100' height='100' fill='" + color + "' />" +
            "<text x='50' y='50' font-family='Arial, sans-serif' font-weight='bold' font-size='50' fill='white' text-anchor='middle' dy='.35em'>" + initial + "</text>" +
            "</svg>";

          ctx.response().putHeader("Content-Type", "image/svg+xml").end(svg);
        }
      }).onFailure(err -> ctx.response().setStatusCode(404).end());
    });

    router.post("/login").handler(ctx -> {
      String username = ctx.request().getFormAttribute("username");
      String password = ctx.request().getFormAttribute("password");
      String rememberMe = ctx.request().getFormAttribute("remember");
      String hashPath = "storage/" + username + "/password.hash";

      vertx.fileSystem().exists(hashPath).onSuccess(exists -> {
        if (!exists) {
          ctx.put("error", "Compte inexistant.");
          engine.render(ctx.data(), "templates/login.peb").onSuccess(buf -> ctx.response().end(buf));
        } else {
          vertx.fileSystem().readFile(hashPath).onSuccess(buffer -> {
            if (buffer.toString().equals(hashPassword(password))) {
              ctx.session().put("user", username);
              if ("on".equals(rememberMe)) {
                ctx.response().addCookie(io.vertx.core.http.Cookie.cookie("remember_user", username)
                  .setMaxAge(30L * 24 * 60 * 60).setPath("/").setHttpOnly(true));
              }
              ctx.redirect("/box");
            } else {
              ctx.put("error", "Mot de passe faux.");
              engine.render(ctx.data(), "templates/login.peb").onSuccess(buf -> ctx.response().end(buf));
            }
          });
        }
      });
    });
// --- ROUTE SPÉCIALE POUR LE MOBILE ---
    router.post("/api/login").handler(ctx -> {
      String u = ctx.request().getFormAttribute("username");
      String p = ctx.request().getFormAttribute("password");String hashPath = "storage/" + u + "/password.hash";

      vertx.fileSystem().readFile(hashPath).onSuccess(buf -> {
        if (buf.toString().equals(hashPassword(p))) {
          // On répond en JSON pour le téléphone
          ctx.json(new io.vertx.core.json.JsonObject().put("status", "ok").put("username", u));
        } else {
          ctx.json(new io.vertx.core.json.JsonObject().put("status", "error").put("message", "Mot de passe incorrect"));
        }
      }).onFailure(e -> ctx.json(new io.vertx.core.json.JsonObject().put("status", "error").put("message", "Utilisateur inconnu")));
    });


    // --- ROUTES MOT DE PASSE OUBLIÉ ---
    router.get("/forgot-password").handler(ctx -> {
      engine.render(ctx.data(), "templates/forgot-password.peb")
        .onSuccess(buf -> ctx.response().putHeader("content-type", "text/html").end(buf));
    });

    router.post("/forgot-password").handler(ctx -> {
      String username = ctx.request().getFormAttribute("username");
      vertx.fileSystem().exists("storage/" + username).onSuccess(exists -> {
        if (exists) {
          ctx.redirect("/reset-password?username=" + username);
        } else {
          ctx.put("error", "Utilisateur introuvable.");
          engine.render(ctx.data(), "templates/forgot-password.peb").onSuccess(buf -> ctx.response().end(buf));
        }
      });
    });

    router.get("/reset-password").handler(ctx -> {
      String username = ctx.request().getParam("username");
      if (username == null) { ctx.redirect("/forgot-password"); return; }
      ctx.put("username", username);
      engine.render(ctx.data(), "templates/reset-password.peb")
        .onSuccess(buf -> ctx.response().putHeader("content-type", "text/html").end(buf));
    });

    router.post("/reset-password").handler(ctx -> {
      String username = ctx.request().getFormAttribute("username");
      String newPassword = ctx.request().getFormAttribute("newPassword");
      String confirmPassword = ctx.request().getFormAttribute("confirmPassword");
      ctx.put("username", username);

      if (!newPassword.equals(confirmPassword)) {
        ctx.put("error", "Les mots de passe ne correspondent pas.");
        engine.render(ctx.data(), "templates/reset-password.peb").onSuccess(buf -> ctx.response().end(buf));
        return;
      }
      if (!PASSWORD_PATTERN.matcher(newPassword).matches()) {
        ctx.put("error", "Critères de sécurité non respectés.");
        engine.render(ctx.data(), "templates/reset-password.peb").onSuccess(buf -> ctx.response().end(buf));
        return;
      }

      String hashPath = "storage/" + username + "/password.hash";
      vertx.fileSystem().writeFile(hashPath, Buffer.buffer(hashPassword(newPassword)))
        .onSuccess(v -> ctx.redirect("/?success=reset"))
        .onFailure(err -> {
          ctx.put("error", "Erreur système.");
          engine.render(ctx.data(), "templates/reset-password.peb").onSuccess(buf -> ctx.response().end(buf));
        });
    });

    router.get("/logout").handler(ctx -> {
      ctx.session().destroy();
      ctx.response().addCookie(io.vertx.core.http.Cookie.cookie("remember_user", "").setMaxAge(0).setPath("/"));
      ctx.redirect("/");
    });

    // --- AUTH MIDDLEWARE (SECURITÉ) ---
    router.route().handler(ctx -> {
      String path = ctx.request().path();
      if (path.startsWith("/api/") || path.startsWith("/attachment/") || path.startsWith("/avatar/") ||
        List.of("/", "/login", "/register", "/style.css", "/forgot-password", "/reset-password", "/admin/nuke").contains(path)) {
        ctx.next();
        return;
      }
      if (ctx.session().get("user") != null) {
        ctx.next();
      } else {
        io.vertx.core.http.Cookie remember = ctx.request().getCookie("remember_user");
        if (remember != null) {
          ctx.session().put("user", remember.getValue());
          ctx.next();
        } else {
          ctx.redirect("/");
        }
      }
    });

    // --- ROUTES PROTEGEES (BOITE MAIL WEB) ---

    router.post("/toggle-important").handler(ctx -> {
      String username = ctx.session().get("user");
      String folder = ctx.request().getFormAttribute("folder");
      String filename = ctx.request().getFormAttribute("filename");
      String path = "storage/" + username + "/" + folder + "/" + filename;

      vertx.fileSystem().readFile(path).compose(buffer -> {
        JsonObject mail = new JsonObject(buffer);
        mail.put("isImportant", !mail.getBoolean("isImportant", false));
        return vertx.fileSystem().writeFile(path, mail.toBuffer());
      }).onComplete(res -> ctx.redirect("/box?folder=" + folder));
    });

    router.get("/settings").handler(ctx -> {
      String user = ctx.session().get("user");
      ctx.put("username", user);
      countUnread(user).onSuccess(count -> {
        ctx.put("unreadCount", count);
        engine.render(ctx.data(), "templates/settings.peb").onSuccess(buf -> ctx.response().end(buf));
      });
    });

    router.post("/settings/avatar").handler(ctx -> {
      String user = ctx.session().get("user");
      if (!ctx.fileUploads().isEmpty()) {
        FileUpload upload = ctx.fileUploads().get(0);
        String target = "storage/avatars/" + user;
        resizeAndSaveAvatar(upload.uploadedFileName(), target)
          .onComplete(res -> {
              avatarCache.remove(user); // Invalider le cache
              ctx.redirect("/settings");
          });
      } else {
        ctx.redirect("/settings");
      }
    });

    router.post("/settings/password").handler(ctx -> {
      String user = ctx.session().get("user");
      String oldPassword = ctx.request().getFormAttribute("oldPassword");
      String newPassword = ctx.request().getFormAttribute("newPassword");
      String confirmPassword = ctx.request().getFormAttribute("confirmPassword");
      ctx.put("username", user);

      if (!newPassword.equals(confirmPassword) || !PASSWORD_PATTERN.matcher(newPassword).matches()) {
        ctx.put("error", "Erreur de validation.");
        engine.render(ctx.data(), "templates/settings.peb").onSuccess(buf -> ctx.response().end(buf));
        return;
      }

      String hashPath = "storage/" + user + "/password.hash";
      vertx.fileSystem().readFile(hashPath).onSuccess(buffer -> {
        if (buffer.toString().equals(hashPassword(oldPassword))) {
          vertx.fileSystem().writeFile(hashPath, Buffer.buffer(hashPassword(newPassword)))
            .onSuccess(v -> {
              ctx.put("success", "Mot de passe modifié !");
              engine.render(ctx.data(), "templates/settings.peb").onSuccess(buf -> ctx.response().end(buf));
            });
        } else {
          ctx.put("error", "Ancien mot de passe incorrect.");
          engine.render(ctx.data(), "templates/settings.peb").onSuccess(buf -> ctx.response().end(buf));
        }
      });
    });

    router.get("/compose").handler(ctx -> {
      String user = ctx.session().get("user");
      String draftId = ctx.request().getParam("draftId");
      ctx.put("username", user);
      ctx.put("recipient", ctx.request().getParam("recipient"));
      ctx.put("subject", ctx.request().getParam("subject"));
      ctx.put("draftId", draftId);

      Future<Object> loadDraftFuture = Future.succeededFuture();
      if (draftId != null) {
        loadDraftFuture = vertx.fileSystem().readFile("storage/" + user + "/draft/" + draftId)
          .map(buffer -> {
            JsonObject draft = new JsonObject(buffer);
            ctx.put("recipient", draft.getString("to"));
            ctx.put("subject", draft.getString("subject"));
            ctx.put("content", draft.getString("content"));
            return null;
          }).recover(err -> Future.succeededFuture());
      }

      loadDraftFuture.compose(v -> countUnread(user)).onSuccess(count -> {
        ctx.put("unreadCount", count);
        engine.render(ctx.data(), "templates/compose.peb").onSuccess(buf -> ctx.response().end(buf));
      });
    });

    // ============================================================
    // --- GESTION ENVOI (LOGIQUE UNIFIÉE WEB & MOBILE) ---
    // ============================================================

    // Route Web & Mobile fusionnées pour gérer les fichiers correctement
    router.post("/send").handler(this::handleUnifiedSend);
    router.post("/api/send").handler(this::handleUnifiedSend);

    router.get("/attachment/:hash").handler(ctx -> {
      String path = "storage/attachments/" + ctx.request().getParam("hash");
      String originalName = ctx.request().getParam("name");
      vertx.fileSystem().exists(path).onSuccess(exists -> {
        if (exists) {
          if (originalName != null) {
            // Force l'extension lors du téléchargement sur PC
            ctx.response().putHeader("Content-Disposition", "attachment; filename=\"" + originalName + "\"");
          }
          ctx.response().sendFile(path);
        } else ctx.response().setStatusCode(404).end();
      });
    });

    router.post("/api/draft").handler(ctx -> {
      // 1. Récupération de l'utilisateur (Session ou Mobile)
      String sender = (ctx.session() != null && ctx.session().get("user") != null)
        ? ctx.session().get("user").toString()
        : ctx.request().getFormAttribute("sender");

      if (sender == null) {
        ctx.response().setStatusCode(400).end("Utilisateur non identifié");
        return;
      }

      // 2. Préparation du JSON
      JsonObject mail = new JsonObject()
        .put("from", sender)
        .put("to", ctx.request().getFormAttribute("recipient"))
        .put("subject", ctx.request().getFormAttribute("subject"))
        .put("content", ctx.request().getFormAttribute("content"))
        .put("date", java.time.Instant.now().toString());

      String draftId = ctx.request().getFormAttribute("draftId");
      String filename = (draftId != null && !draftId.isEmpty()) ? draftId : (System.currentTimeMillis() + ".json");

      // 3. FORCE la création du dossier "draft" s'il n'existe pas
      String userDraftDir = "storage/" + sender + "/draft";

      vertx.fileSystem().mkdirs(userDraftDir).onComplete(ar -> {
        if (ar.succeeded()) {
          // 4. Écriture du fichier seulement si le dossier existe
          vertx.fileSystem().writeFile(userDraftDir + "/" + filename, mail.toBuffer())
            .onSuccess(v -> {
              System.out.println("💾 Brouillon enregistré pour " + sender + " -> " + filename);

              if (ctx.request().getFormAttribute("sender") != null) {
                ctx.json(new JsonObject().put("status", "ok").put("id", filename));
              } else {
                ctx.redirect("/box?folder=draft");
              }
            })
            .onFailure(err -> {
              err.printStackTrace();
              ctx.fail(500);
            });
        } else {
          ctx.fail(500);
        }
      });
    });

    // --- ROUTE API DELETE (CORRIGÉE AVEC LOGS) ---
    router.post("/api/delete").handler(ctx -> {
      String username = ctx.request().getFormAttribute("username");
      String folder = ctx.request().getFormAttribute("folder");
      String filename = ctx.request().getFormAttribute("id"); // Android envoie 'id'

      System.out.println("🗑️ Tentative de suppression : " + username + " / " + folder + " / " + filename);

      if (username == null || folder == null || filename == null) {
        System.err.println("❌ Paramètres manquants pour la suppression");
        ctx.json(new JsonObject().put("status", "error").put("message", "Manquant"));
        return;
      }

      String src = "storage/" + username + "/" + folder + "/" + filename;
      String dest = "storage/" + username + "/trash/" + filename;

      vertx.fileSystem().exists(src).onSuccess(exists -> {
          if (!exists) {
              System.err.println("❌ Fichier introuvable : " + src);
              ctx.json(new JsonObject().put("status", "error").put("message", "Fichier introuvable"));
              return;
          }

          if ("trash".equals(folder)) {
            // Suppression définitive
            vertx.fileSystem().delete(src).onComplete(res -> {
              if (res.succeeded()) {
                  System.out.println("✅ Fichier supprimé définitivement : " + src);
                  ctx.json(new JsonObject().put("status", "deleted"));
              } else {
                  System.err.println("❌ Erreur suppression : " + res.cause().getMessage());
                  ctx.fail(500);
              }
            });
          } else {
            // Déplacement vers la corbeille
            vertx.fileSystem().move(src, dest, new CopyOptions().setReplaceExisting(true)).onComplete(res -> {
              if (res.succeeded()) {
                  System.out.println("✅ Fichier déplacé vers la corbeille : " + dest);
                  ctx.json(new JsonObject().put("status", "moved_to_trash"));
              } else {
                  System.err.println("❌ Erreur déplacement : " + res.cause().getMessage());
                  ctx.fail(500);
              }
            });
          }
      }).onFailure(err -> {
          System.err.println("❌ Erreur vérification fichier : " + err.getMessage());
          ctx.fail(500);
      });
    });

    router.get("/read").handler(ctx -> {
      String username = ctx.session().get("user");
      String folder = ctx.request().getParam("folder");
      String id = ctx.request().getParam("id");
      String path = "storage/" + username + "/" + folder + "/" + id;

      vertx.fileSystem().readFile(path).compose(buffer -> {
        JsonObject mail = new JsonObject(buffer);
        if (!mail.getBoolean("isRead", false)) {
          mail.put("isRead", true);
          return vertx.fileSystem().writeFile(path, mail.toBuffer()).map(v -> mail);
        }
        return Future.succeededFuture(mail);
      }).compose(mail ->
        Future.all(countUnread(username), calculateUserSpace(username)).map(c -> {
          ctx.put("username", username).put("folder", folder).put("id", id).put("mail", mail)
            .put("unreadCount", c.resultAt(0)).put("userSpace", c.resultAt(1));
          return null;
        })
      ).onSuccess(v -> engine.render(ctx.data(), "templates/read.peb").onSuccess(buf -> ctx.response().end(buf)));
    });

    router.get("/box").handler(ctx -> {
      String username = ctx.session().get("user");
      String folder = ctx.request().getParam("folder") == null ? "inbox" : ctx.request().getParam("folder");
      String query = ctx.request().getParam("q");
      String path = "storage/" + username + "/" + folder;

      vertx.fileSystem().readDir(path).compose(files -> {
          List<JsonObject> mails = new ArrayList<>();
          Future<Object> chain = Future.succeededFuture();
          for (String p : files) {
            chain = chain.compose(v -> vertx.fileSystem().readFile(p).map(buf -> {
              try {
                JsonObject json = new JsonObject(buf);
                json.put("id", new File(p).getName());
                if (query == null || json.getString("subject", "").toLowerCase().contains(query.toLowerCase())
                  || json.getString("from", "").toLowerCase().contains(query.toLowerCase())) {
                  mails.add(json);
                }
              } catch (Exception e) {}
              return null;
            }));
          }
          return chain.map(v -> mails);
        }).compose(mails -> {
          mails.sort((m1, m2) -> m2.getString("id").compareTo(m1.getString("id")));
          return Future.all(countUnread(username), calculateUserSpace(username)).map(c -> {
            ctx.put("username", username).put("mails", mails).put("folder", folder)
              .put("unreadCount", c.resultAt(0)).put("userSpace", c.resultAt(1)).put("query", query);
            return null;
          });
        }).onSuccess(v -> engine.render(ctx.data(), "templates/inbox.peb").onSuccess(buf -> ctx.response().end(buf)))
        .onFailure(err -> {
          ctx.put("username", username).put("mails", new ArrayList<>()).put("unreadCount", 0);
          engine.render(ctx.data(), "templates/inbox.peb").onSuccess(buf -> ctx.response().end(buf));
        });
    });

    router.post("/api/register").handler(ctx -> {
      String u = ctx.request().getFormAttribute("username");
      String p = ctx.request().getFormAttribute("password");
      String avatar = ctx.request().getFormAttribute("avatar");

      if (u == null || p == null) {
        ctx.json(new JsonObject().put("status", "error").put("message", "Données manquantes"));
        return;
      }

      String base = "storage/" + u;

      // 1. On crée les dossiers
      vertx.fileSystem().mkdirs(base + "/inbox")
        .compose(v -> vertx.fileSystem().mkdirs(base + "/outbox"))
        .compose(v -> vertx.fileSystem().mkdirs(base + "/trash"))
        // 2. On écrit le mot de passe (on attend que ce soit fini)
        .compose(v -> vertx.fileSystem().writeFile(base + "/password.hash", Buffer.buffer(hashPassword(p))))
        // 3. Gestion de l'avatar avec nettoyage spécifique mobile
        .compose(v -> {
          if (avatar != null && !avatar.isEmpty()) {
            try {
              // NETTOYAGE : Supprime le préfixe "data:image/xxx;base64," si présent (très fréquent sur mobile)
              String cleanBase64 = avatar.replaceAll("(?i)data:image/[^;]+;base64,", "").replaceAll("\\s", "");
              byte[] imgData = java.util.Base64.getDecoder().decode(cleanBase64);

              return vertx.fileSystem().writeFile("storage/avatars/" + u, Buffer.buffer(imgData));
            } catch (Exception e) {
              // Si le décodage échoue, on renvoie une erreur spécifique
              return Future.failedFuture("Erreur décodage image : " + e.getMessage());
            }
          }
          return Future.succeededFuture();
        })
        // 4. Succès final : On ne répond que quand TOUT est écrit sur le disque
        .onSuccess(v -> ctx.json(new JsonObject().put("status", "ok")))
        // 5. En cas d'erreur (dossier existant, disque plein, base64 invalide...)
        .onFailure(err -> {
          err.printStackTrace(); // Regarde tes logs serveur pour voir l'erreur précise
          ctx.json(new JsonObject().put("status", "error").put("reason", err.getMessage()));
        });
    });


    router.get("/api/mails").handler(ctx -> {
      String username = ctx.request().getParam("username");
      String folder = ctx.request().getParam("folder");

      if (username == null || folder == null) {
        ctx.json(new JsonObject().put("status", "error").put("message", "Manquant"));
        return;
      }

      String relativePath = "storage/" + username + "/" + folder;

      vertx.fileSystem().exists(relativePath).onSuccess(exists -> {
        if (!exists) {
          ctx.json(new JsonObject().put("mails", new JsonArray()));
          return;
        }

        vertx.fileSystem().readDir(relativePath).onSuccess(files -> {
          // --- OPTIMISATION 1 : TRIER PAR DATE (NOM DE FICHIER DESC) ---
          List<String> jsonFiles = new ArrayList<>();
          for (String f : files) if (f.endsWith(".json")) jsonFiles.add(f);

          Collections.sort(jsonFiles, Collections.reverseOrder());

          // --- OPTIMISATION 2 : LIMITER AUX 50 DERNIERS AVANT LA LECTURE ---
          int limit = Math.min(jsonFiles.size(), 50);
          List<String> limitedFiles = jsonFiles.subList(0, limit);

          List<Future<JsonObject>> futures = new ArrayList<>();

          for (String filePath : limitedFiles) {
            futures.add(vertx.fileSystem().readFile(filePath).compose(buffer -> {
              try {
                JsonObject mailJson = new JsonObject(buffer);
                mailJson.put("id", new File(filePath).getName());

                // --- OPTIMISATION 3 : CACHE D'AVATAR ---
                String targetUser = folder.equals("outbox") ? mailJson.getString("to") : mailJson.getString("from");
                if (targetUser != null && targetUser.contains("(")) {
                  targetUser = targetUser.split(" ")[0];
                }

                final String finalTargetUser = targetUser;

                // Si l'image est en mémoire, on ne touche pas au disque
                if (avatarCache.containsKey(finalTargetUser)) {
                  mailJson.put("avatar_base64", avatarCache.get(finalTargetUser));
                  return Future.succeededFuture(mailJson);
                }

                String avatarPath = "storage/avatars/" + finalTargetUser;
                return vertx.fileSystem().exists(avatarPath).compose(avExists -> {
                  if (avExists) {
                    return vertx.fileSystem().readFile(avatarPath).map(imgBuf -> {
                      String b64 = java.util.Base64.getEncoder().encodeToString(imgBuf.getBytes());
                      avatarCache.put(finalTargetUser, b64); // Sauvegarde en mémoire
                      mailJson.put("avatar_base64", b64);
                      return mailJson;
                    });
                  }
                  return Future.succeededFuture(mailJson);
                });
              } catch (Exception e) {
                return Future.succeededFuture(null);
              }
            }));
          }

          Future.all(futures).onSuccess(res -> {
            JsonArray mailsArray = new JsonArray();
            for (int i = 0; i < res.size(); i++) {
              JsonObject m = res.resultAt(i);
              if (m != null) mailsArray.add(m);
            }
            ctx.json(new JsonObject().put("mails", mailsArray));
          }).onFailure(err -> ctx.fail(500));
        });
      }).onFailure(err -> ctx.json(new JsonObject().put("mails", new JsonArray())));
    });

    router.get("/api/storage-info").handler(ctx -> {
      calculateUserSpace(ctx.request().getParam("username")).onSuccess(s ->
        ctx.json(new JsonObject().put("sizeReadable", s))
      ).onFailure(e -> ctx.json(new JsonObject().put("sizeReadable", "0 Ko")));
    });

    router.get("/api/user-profile").handler(ctx -> {
      String username = ctx.request().getParam("username");
      String path = "storage/avatars/" + username;
      vertx.fileSystem().exists(path).onSuccess(exists -> {
        if (exists) {
          vertx.fileSystem().readFile(path).onSuccess(buffer -> {
            String encoded = java.util.Base64.getEncoder().encodeToString(buffer.getBytes());
            ctx.json(new JsonObject().put("avatar_base64", encoded));
          });
        } else {
          ctx.json(new JsonObject().put("avatar_base64", ""));
        }
      }).onFailure(err -> ctx.json(new JsonObject().put("avatar_base64", "")));
    });

    // --- MISE À JOUR DE L'AVATAR DEPUIS LE MOBILE ---
    router.post("/api/settings/avatar").handler(ctx -> {
      String u = ctx.request().getFormAttribute("username");
      String b64 = ctx.request().getFormAttribute("avatar");

      if (u == null || b64 == null) {
        ctx.fail(400);
        return;
      }

      // On décode l'image Base64 envoyée par le téléphone
      byte[] imgData = java.util.Base64.getDecoder().decode(b64.replaceAll("\\s", ""));

      // On écrase l'ancien fichier avatar par le nouveau
      vertx.fileSystem().writeFile("storage/avatars/" + u, io.vertx.core.buffer.Buffer.buffer(imgData))
        .onSuccess(v -> {
          System.out.println("📸 Avatar mis à jour pour : " + u);
          // Si vous avez ajouté le système de cache, n'oubliez pas de le vider ici :
          // avatarCache.remove(u);
          ctx.json(new io.vertx.core.json.JsonObject().put("status", "ok"));
        })
        .onFailure(err -> ctx.fail(500));
    });


    router.post("/api/mark-read").handler(ctx -> {
      String u = ctx.request().getFormAttribute("username");
      String f = ctx.request().getFormAttribute("folder");
      String id = ctx.request().getFormAttribute("id");
      String path = "storage/" + u + "/" + f + "/" + id;

      vertx.fileSystem().readFile(path).onSuccess(buf -> {
        JsonObject mail = new JsonObject(buf);
        mail.put("isRead", true); // On change l'état dans le JSON
        vertx.fileSystem().writeFile(path, mail.toBuffer()).onSuccess(v -> {
          ctx.json(new JsonObject().put("status", "ok"));
        });
      }).onFailure(e -> ctx.fail(404));
    });
    // --- SERVEUR UDP ---
    DatagramSocket socket = vertx.createDatagramSocket();
    socket.listen(9999, "0.0.0.0").onSuccess(so -> {
      System.out.println("👻 Serveur UDP sur 9999");
      socket.handler(packet -> {
        String ip = packet.sender().host();
        int p = packet.sender().port();
        int count = ipCounts.getOrDefault(ip, 0);
        if (count >= 10) {
          socket.send(Buffer.buffer("Erreur : Limite atteinte."), p, ip);
          return;
        }
        ipCounts.put(ip, count + 1);
        String data = packet.data().toString();
        String[] lines = data.split("\n", 3);
        if (lines.length >= 3) {
          String recipient = lines[0].trim();
          String subject = lines[1].trim();
          String content = lines[2].trim();
          JsonObject mail = new JsonObject()
            .put("from", "Anonyme (" + ip + ")").put("to", recipient)
            .put("date", java.time.Instant.now().toString())
            .put("subject", "[UDP] " + subject).put("content", content).put("isRead", false);
          String filename = "udp_" + System.currentTimeMillis() + ".json";
          String path = "storage/" + recipient + "/inbox/" + filename;
          vertx.fileSystem().exists("storage/" + recipient + "/inbox").onSuccess(exists -> {
            if (exists) {
              vertx.fileSystem().writeFile(path, mail.toBuffer()).onSuccess(v -> {
                if (activeSockets.containsKey(recipient)) {
                  activeSockets.get(recipient).writeTextMessage("NEW_MAIL");
                }
                socket.send(Buffer.buffer("Bien recu !"), p, ip);
              });
            } else {
              socket.send(Buffer.buffer("Destinataire inconnu."), p, ip);
            }
          });
        }
      });
    });

    // --- NETTOYAGE AUTO ---
    long MAX_AGE = 30L * 24 * 60 * 60 * 1000L; // 30 jours
    vertx.setPeriodic(10000, id -> {
      vertx.fileSystem().readDir("storage").onSuccess(users -> {
        for (String userPath : users) {
          vertx.fileSystem().readDir(userPath + "/trash").onSuccess(files -> {
            for (String filePath : files) {
              vertx.fileSystem().props(filePath).onSuccess(props -> {
                if (System.currentTimeMillis() - props.lastModifiedTime() > MAX_AGE) {
                  vertx.fileSystem().delete(filePath);
                }
              });
            }
          });
        }
      });
    });

    // --- DEMARRAGE SERVEUR (LOGS) ---
    int port = 8080;
    if (System.getenv("PORT") != null) {
      try { port = Integer.parseInt(System.getenv("PORT")); } catch (Exception e) {}
    }

    vertx.createHttpServer().requestHandler(router).listen(port, "0.0.0.0") // AJOUT DE "0.0.0.0" ICI
      .onSuccess(s -> {
        startPromise.complete();
        System.out.println("✅ Serveur Web ouvert au monde sur le port " + s.actualPort());
        System.out.println("➡️  Lien local : http://localhost:" + s.actualPort());
      })
      .onFailure(startPromise::fail);
  }


  private void handleUnifiedSend(io.vertx.ext.web.RoutingContext ctx) {
    String sender = (ctx.session() != null && ctx.session().get("user") != null)
      ? ctx.session().get("user")
      : ctx.request().getFormAttribute("sender");

    String recipient = ctx.request().getFormAttribute("recipient");
    String subject = ctx.request().getFormAttribute("subject");
    String content = ctx.request().getFormAttribute("content");
    String draftId = ctx.request().getFormAttribute("draftId");
    List<FileUpload> uploads = ctx.fileUploads();

    List<Future<JsonObject>> attachmentFutures = new ArrayList<>();
    for (FileUpload upload : uploads) {
      // CORRECTION : Ignorer les fichiers vides
      if (upload.fileName() == null || upload.fileName().isEmpty() || upload.size() == 0) {
          continue;
      }

      attachmentFutures.add(vertx.executeBlocking(() -> {
        String hash = calculateSHA256(upload.uploadedFileName());
        String targetPath = "storage/attachments/" + hash;
        if (!new File(targetPath).exists()) new File(upload.uploadedFileName()).renameTo(new File(targetPath));
        else new File(upload.uploadedFileName()).delete();

        // Retourne les infos complètes (Nom et Type MIME) pour que le PC les reconnaisse
        return new JsonObject()
          .put("name", upload.fileName())
          .put("hash", hash)
          .put("size", upload.size())
          .put("type", upload.contentType());
      }));
    }

    Future.all(attachmentFutures).onSuccess(composite -> {
      JsonArray attachments = new JsonArray();
      for (int i = 0; i < composite.size(); i++) attachments.add(composite.<JsonObject>resultAt(i));

      JsonObject mail = new JsonObject()
        .put("from", sender).put("to", recipient)
        .put("date", java.time.Instant.now().toString())
        .put("subject", subject).put("content", content)
        .put("isRead", false).put("attachments", attachments);

      String filename = System.currentTimeMillis() + ".json";
      vertx.fileSystem().writeFile("storage/" + recipient + "/inbox/" + filename, mail.toBuffer())
        .onSuccess(v -> {
          if (activeSockets.containsKey(recipient)) activeSockets.get(recipient).writeTextMessage("NEW_MAIL");

          // Copie dans les messages envoyés
          vertx.fileSystem().writeFile("storage/" + sender + "/outbox/" + filename, mail.copy().put("isRead", true).toBuffer())
            .onSuccess(v2 -> {
              if (draftId != null && !draftId.isEmpty()) vertx.fileSystem().delete("storage/" + sender + "/draft/" + draftId);
              if (ctx.session() != null && ctx.session().get("user") != null) ctx.redirect("/box?folder=outbox");
              else ctx.json(new JsonObject().put("status", "ok"));
            });
        }).onFailure(e -> ctx.response().end("Erreur destinataire"));
    });
  }

  // --- HELPERS : IMAGE & SECURITY (FIXED FOR VERT.X 4.x) ---

  private Future<Void> resizeAndSaveAvatar(String sourcePath, String targetPath) {
    return vertx.executeBlocking(() -> {
      try {
        BufferedImage inputImage = ImageIO.read(new File(sourcePath));
        BufferedImage outputImage = new BufferedImage(200, 200, BufferedImage.TYPE_INT_RGB);
        Graphics2D g2d = outputImage.createGraphics();
        g2d.setRenderingHint(RenderingHints.KEY_INTERPOLATION, RenderingHints.VALUE_INTERPOLATION_BILINEAR);
        g2d.drawImage(inputImage, 0, 0, 200, 200, null);
        g2d.dispose();
        ImageIO.write(outputImage, "jpg", new File(targetPath));
        new File(sourcePath).delete();
      } catch (Exception e) { e.printStackTrace(); }
      return null;
    });
  }

  private Future<String> calculateUserSpace(String username) {
    String base = "storage/" + username;
    List<String> folders = List.of("inbox", "outbox", "draft", "trash");
    List<Future<?>> futures = new ArrayList<>();
    for(String f : folders) {
      futures.add(vertx.fileSystem().readDir(base + "/" + f).compose(files -> {
        List<Future<?>> sizes = new ArrayList<>();
        for(String file : files) sizes.add(vertx.fileSystem().readFile(file).map(b -> (long)b.length()));
        return Future.all(sizes).map(c -> {
          long sum = 0;
          for(int i=0; i<c.size(); i++) sum += (Long)c.resultAt(i);
          return sum;
        });
      }).recover(e -> Future.succeededFuture(0L)));
    }
    return Future.all(futures).map(c -> {
      long total = 0;
      for(int i=0; i<c.size(); i++) total += (Long)c.resultAt(i);
      if (total < 1024) return total + " o";
      if (total < 1024*1024) return String.format("%.1f Ko", total/1024.0);
      return String.format("%.1f Mo", total/(1024.0*1024.0));
    });
  }

  private Future<Long> countUnread(String user) {
    return vertx.fileSystem().readDir("storage/" + user + "/inbox").compose(files -> {
      List<Future<?>> checks = new ArrayList<>();
      for(String f : files) checks.add(vertx.fileSystem().readFile(f).map(b -> !new JsonObject(b).getBoolean("isRead", false)));
      return Future.all(checks).map(c -> {
        long count = 0;
        for(int i=0; i<c.size(); i++) if((Boolean)c.resultAt(i)) count++;
        return count;
      });
    }).recover(e -> Future.succeededFuture(0L));
  }

  private String calculateSHA256(String path) {
    try {
      MessageDigest md = MessageDigest.getInstance("SHA-256");
      FileInputStream fis = new FileInputStream(path);
      byte[] b = new byte[1024]; int n;
      while((n=fis.read(b)) != -1) md.update(b, 0, n);
      StringBuilder sb = new StringBuilder();
      for(byte bt : md.digest()) sb.append(String.format("%02x", bt));
      fis.close();
      return sb.toString();
    } catch(Exception e) { return "error"; }
  }

  private String hashPassword(String p) {
    try {
      byte[] h = MessageDigest.getInstance("SHA-256").digest(p.getBytes(StandardCharsets.UTF_8));
      StringBuilder sb = new StringBuilder();
      for(byte b : h) sb.append(String.format("%02x", b));
      return sb.toString();
    } catch(Exception e) { throw new RuntimeException(e); }
  }

  public static void main(String[] args) {
    io.vertx.core.Vertx.vertx().deployVerticle(new MainVerticle());
  }
}
