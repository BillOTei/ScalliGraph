package org.thp.scalligraph.services.config

import scala.concurrent.ExecutionContext
import scala.concurrent.duration.{Duration, FiniteDuration}
import scala.util.{Failure, Success, Try}

import play.api.libs.functional.syntax._
import play.api.libs.json._
import play.api.{ConfigLoader, Configuration, Logger}

import akka.actor.{ActorRef, ActorSystem}
import com.typesafe.config.{Config, ConfigFactory, ConfigRenderOptions}
import javax.inject.{Inject, Named, Singleton}
import org.thp.scalligraph.NotFoundError
import org.thp.scalligraph.auth.AuthContext
import org.thp.scalligraph.models.Database
import org.thp.scalligraph.services.EventSrv

@Singleton
class ApplicationConfig @Inject()(
    configuration: Configuration,
    db: Database,
    system: ActorSystem,
    eventSrv: EventSrv,
    @Named("config-actor") configActor: ActorRef,
    implicit val ec: ExecutionContext
) {
  lazy val logger                          = Logger(getClass)
  val ignoreDatabaseConfiguration: Boolean = configuration.get[Boolean]("ignoreDatabaseConfiguration")
  if (ignoreDatabaseConfiguration) logger.warn("Emit warning !") // TODO
  private val itemsLock                                = new Object
  private var items: Map[String, ConfigItemImpl[_, _]] = Map.empty

  def item[T: Format](path: String, description: String): ConfigItem[T, T] =
    validatedMapItem[T, T](path, description, Success.apply, identity)

  def mapItem[B: Format, F](path: String, description: String, mapFunction: B => F): ConfigItem[B, F] =
    validatedMapItem[B, F](path, description, Success.apply, mapFunction)

  def validatedItem[T: Format](path: String, description: String, validation: T => Try[T]): ConfigItem[T, T] =
    validatedMapItem[T, T](path, description, validation, identity)

  def validatedMapItem[B: Format, F](path: String, description: String, validation: B => Try[B], mapFunction: B => F): ConfigItem[B, F] = {
    implicit val configLoader: ConfigLoader[B] = (config: Config, path: String) =>
      Json.parse(config.getValue(path).render(ConfigRenderOptions.concise())).as[B]

    itemsLock.synchronized {
      items
        .getOrElse(
          path, {
            val configItem =
              new ConfigItemImpl[B, F](
                path,
                description,
                configuration.get[B](path),
                implicitly[Format[B]],
                validation,
                mapFunction,
                db,
                eventSrv,
                configActor,
                ec
              )
            items = items + (path -> configItem)
            configItem
          }
        )
        .asInstanceOf[ConfigItem[B, F]]
    }
  }

  def context[C](context: ConfigContext[C]): ContextApplicationConfig[C] =
    new ContextApplicationConfig[C](context, configuration, db, eventSrv, configActor, ec)

  def list: Seq[ConfigItem[_, _]] = items.values.toSeq

  def set(path: String, value: JsValue)(implicit authContext: AuthContext): Try[Unit] = items.get(path) match {
    case Some(i) => i.setJson(value)
    case None    => Failure(NotFoundError(s"Configuration $path not found"))
  }
}

class ContextApplicationConfig[C](
    context: ConfigContext[C],
    configuration: Configuration,
    db: Database,
    eventSrv: EventSrv,
    configActor: ActorRef,
    implicit val ec: ExecutionContext
) {
  lazy val logger = Logger(getClass)

  def item[T: Format](path: String, description: String): ContextConfigItem[T, C] =
    validatedItem[T](path, description, Success.apply)

  def validatedItem[T: Format](path: String, description: String, validation: T => Try[T]): ContextConfigItem[T, C] = {
    implicit val configLoader: ConfigLoader[T] = (config: Config, path: String) =>
      Json.parse(config.getValue(path).render(ConfigRenderOptions.concise())).as[T]

    new ContextConfigItemImpl(
      context,
      path,
      description,
      configuration.get[T](context.defaultPath(path)),
      implicitly[Format[T]],
      validation,
      db,
      eventSrv,
      configActor,
      ec
    )
  }
}

object ApplicationConfig {
  implicit val configurationFormat: Format[Configuration] = Format(
    Reads[Configuration](json => JsSuccess(Configuration(ConfigFactory.parseString(json.toString)))),
    Writes[Configuration](conf => JsObject(conf.entrySet.map { case (k, v) => k -> Json.parse(v.render(ConfigRenderOptions.concise())) }.toSeq))
  )
  implicit val durationFormat: Format[Duration] = implicitly[Format[String]].inmap(Duration.apply, _.toString)

  implicit val finiteDurationFormat: Format[FiniteDuration] = Format[FiniteDuration](
    Reads {
      case JsString(s) =>
        Duration(s) match {
          case d: FiniteDuration => JsSuccess(d)
          case _                 => JsError(s"$s is not a valid finite duration")
        }
      case other => JsError(s"$other is not a valid finite duration")
    },
    Writes(d => Option(d).map(v => JsString(v.toString)).getOrElse(JsNull))
  )
}
