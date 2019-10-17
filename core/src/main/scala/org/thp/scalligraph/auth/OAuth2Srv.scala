package org.thp.scalligraph.auth

import javax.inject.{Inject, Singleton}
import org.thp.scalligraph.auth.GrantType.GrantType
import org.thp.scalligraph.auth.ResponseType.ResponseType
import org.thp.scalligraph.controllers.AuthenticatedRequest
import org.thp.scalligraph.{AuthenticationError, BadConfigurationError}
import play.api.libs.ws.{WSClient, WSResponse}
import play.api.mvc._
import play.api.{Configuration, Logger}

import scala.concurrent.{ExecutionContext, Future}
import scala.util.Try

object GrantType extends Enumeration {
  type GrantType = Value

  val authorizationCode: GrantType = Value("authorization_code")
  // Only this supported atm
}

object ResponseType extends Enumeration {
  type ResponseType = Value

  val code: ResponseType = Value("code")
  // Only this supported atm
}

case class OAuth2Config(
    clientId: String,
    clientSecret: String,
    redirectUri: String,
    responseType: ResponseType,
    grantType: GrantType,
    authorizationUrl: String,
    tokenUrl: String,
    userUrl: String,
    scope: Seq[String],
    autoCreate: Boolean,
    autoUpdate: Boolean
)

class TokenizedRequest[A](token: Option[String], request: Request[A]) extends WrappedRequest[A](request)

class OAuth2Srv(OAuth2Config: OAuth2Config, userSrv: UserSrv, WSClient: WSClient)(implicit ec: ExecutionContext) extends AuthSrv {
  lazy val logger      = Logger(getClass)
  val name: String     = "oauth2"
  val endpoint: String = "ssoLogin"

  override def actionFunction(nextFunction: ActionFunction[Request, AuthenticatedRequest]): ActionFunction[Request, AuthenticatedRequest] =
    OAuth2Config.grantType match {
      case GrantType.authorizationCode =>
        authRedirect
          .andThen(authTokenFromCode)
          .andThen(super.actionFunction(nextFunction))

      case x =>
        new ActionFunction[Request, AuthenticatedRequest] {
          override def invokeBlock[A](request: Request[A], block: AuthenticatedRequest[A] => Future[Result]): Future[Result] =
            Future.failed(BadConfigurationError(s"OAuth GrantType $x not supported yet"))
          override protected def executionContext: ExecutionContext = ec
        }
    }

  private def authRedirect: ActionFilter[Request] = new ActionFilter[Request] {
    private val queryStringParams = Map[String, Seq[String]](
      "scope"         -> Seq(OAuth2Config.scope.mkString(" ")),
      "response_type" -> Seq(ResponseType.code.toString),
      "redirect_uri"  -> Seq(OAuth2Config.redirectUri),
      "client_id"     -> Seq(OAuth2Config.clientId)
    )
    def executionContext: ExecutionContext = ec

    def filter[A](input: Request[A]): Future[Option[Result]] = Future.successful {
      if (input.uri.contains(endpoint) && !input.queryString.contains(ResponseType.code.toString)) {
        logger.debug(s"Redirecting to ${OAuth2Config.redirectUri} with $queryStringParams")
        Some(Results.Redirect(OAuth2Config.authorizationUrl, queryStringParams, status = 200))
      } else None
    }
  }

  private def authTokenFromCode: ActionTransformer[Request, TokenizedRequest] = new ActionTransformer[Request, TokenizedRequest] {
    def executionContext: ExecutionContext = ec

    def transform[A](request: Request[A]): Future[TokenizedRequest[A]] =
      if (!request.uri.contains(endpoint)) {
        Future.successful(new TokenizedRequest[A](None, request))
      } else if (!request.queryString.contains(ResponseType.code.toString)) {
        Future.failed(AuthenticationError(s"OAuth2 server code missing ${request.queryString.get("error")}"))
      } else {
        val code = request.queryString(ResponseType.code.toString).headOption.getOrElse("")

        logger.debug(s"Attempting to retrieve OAuth2 token from ${OAuth2Config.tokenUrl} with code $code")
        Future.successful(new TokenizedRequest[A](None, request))
      }
  }

  private def getAuthTokenFromCode(code: String): Future[String] =
    WSClient
      .url(OAuth2Config.tokenUrl)
      .post(
        Map(
          "code"          -> code,
          "grant_type"    -> OAuth2Config.grantType.toString,
          "client_secret" -> OAuth2Config.clientSecret,
          "redirect_uri"  -> OAuth2Config.redirectUri,
          "client_id"     -> OAuth2Config.clientId
        )
      )
      .recoverWith {
        case error => Future.failed(AuthenticationError(s"OAuth2 token verification failure ${error.getMessage}"))
      }
      .flatMap {
        case r: WSResponse if r.status == 200 => Future.successful((r.json \ "access_token").asOpt[String].getOrElse(""))
        case _                                => Future.failed(AuthenticationError("OAuth2 unexpected response from server"))
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
      responseType     <- configuration.getOrFail[String]("responseType").flatMap(rt => Try(ResponseType.withName(rt)))
      grantType        <- configuration.getOrFail[String]("grantType").flatMap(gt => Try(GrantType.withName(gt)))
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
