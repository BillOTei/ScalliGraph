package org.thp.scalligraph.auth

import javax.inject.{Inject, Singleton}
import org.thp.scalligraph.controllers.AuthenticatedRequest
import play.api.libs.ws.WSClient
import play.api.mvc._
import play.api.{Configuration, Logger}

import scala.concurrent.{ExecutionContext, Future}
import scala.util.Try

case class OAuth2Config(
    clientId: String,
    clientSecret: String,
    redirectUri: String,
    responseType: String,
    grantType: String,
    authorizationUrl: String,
    tokenUrl: String,
    userUrl: String,
    scope: Seq[String],
    autoCreate: Boolean,
    autoUpdate: Boolean
)

class OAuth2Srv(OAuth2Config: OAuth2Config, userSrv: UserSrv, WSClient: WSClient)(implicit ec: ExecutionContext) extends AuthSrv {
  lazy val logger  = Logger(getClass)
  val name: String = "oauth2"

  override def actionFunction(nextFunction: ActionFunction[Request, AuthenticatedRequest]): ActionFunction[Request, AuthenticatedRequest] =
    authRedirect
      .andThen(super.actionFunction(nextFunction))

  private def authRedirect: ActionFilter[Request] = new ActionFilter[Request] {
    private val queryStringParams = Map[String, Seq[String]](
      "scope"         -> Seq(OAuth2Config.scope.mkString(" ")),
      "response_type" -> Seq(OAuth2Config.responseType),
      "redirect_uri"  -> Seq(OAuth2Config.redirectUri),
      "client_id"     -> Seq(OAuth2Config.clientId)
    )
    def executionContext: ExecutionContext = ec

    def filter[A](input: Request[A]): Future[Option[Result]] = Future.successful {
      if (input.uri.contains("ssoLogin"))
        Some(Results.Redirect(OAuth2Config.authorizationUrl, queryStringParams, status = 200))
      else
        None
    }
  }
}

@Singleton
class OAuth2Provider @Inject()(userSrv: UserSrv, config: Configuration, WSClient: WSClient, implicit val executionContext: ExecutionContext)
    extends AuthSrvProvider {
  override val name: String = "oauth2"
  override def apply(configuration: Configuration): Try[AuthSrv] =
    for {
      clientId         <- configuration.getOrFail[String]("clientId")
      clientSecret     <- configuration.getOrFail[String]("clientSecret")
      redirectUri      <- configuration.getOrFail[String]("redirectUri")
      responseType     <- configuration.getOrFail[String]("responseType")
      grantType        <- configuration.getOrFail[String]("grantType")
      authorizationUrl <- configuration.getOrFail[String]("authorizationUrl")
      userUrl          <- configuration.getOrFail[String]("userUrl")
      tokenUrl         <- configuration.getOrFail[String]("tokenUrl")
      scope            <- configuration.getOrFail[Seq[String]]("scope")
      autoCreate = config.getOptional[Boolean]("auth.sso.autoCreate").getOrElse(false)
      autoUpdate = config.getOptional[Boolean]("auth.sso.autoUpdate").getOrElse(false)
    } yield new OAuth2Srv(
      OAuth2Config(clientId, clientSecret, redirectUri, responseType, grantType, authorizationUrl, userUrl, tokenUrl, scope, autoCreate, autoUpdate),
      userSrv,
      WSClient
    )
}
