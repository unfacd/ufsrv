-- MySQL dump 10.13  Distrib 5.7.16, for Linux (x86_64)
--
-- Host: localhost    Database: ufsrv
-- ------------------------------------------------------
-- Server version       5.7.13-0ubuntu0.16.04.2-log

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8 */;
/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;
/*!40103 SET TIME_ZONE='+00:00' */;
/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;

--
-- Table structure for table `accounts`
--

DROP TABLE IF EXISTS `accounts`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
/* INT UNSIGNED 4.3 billion rows */;
CREATE TABLE `accounts` (
  `id` INT(20) UNSIGNED NOT NULL AUTO_INCREMENT,
  `ufsrvuid` binary(16) DEFAULT NULL,
  `uuid` binary(16) DEFAULT NULL,
  `number` varchar(255) NOT NULL,
  `data` json DEFAULT NULL,
  `data_user` json DEFAULT NULL,
  `accounts_authenticated_device_cookie` varchar(255) GENERATED ALWAYS AS (json_unquote(json_extract(`data`,'$.authenticated_device.cookie'))) VIRTUAL,
  `accounts_nickname` varchar(50) GENERATED ALWAYS AS (json_unquote(json_extract(`data_user`,'$.nickname'))) VIRTUAL,
  `accounts_authenticated_device_gcm_id` varchar(255) GENERATED ALWAYS AS (json_unquote(json_extract(`data`,'$.authenticated_device.gcm_id'))) VIRTUAL,
  `uuid_serialised` varchar(36) GENERATED ALWAYS AS
      (insert(
              insert(
                      insert(
                              insert(lower(hex(uuid)),9,0,'-'),
                              14,0,'-'),
                      19,0,'-'),
              24,0,'-')
      ) VIRTUAL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `id_UNIQUE` (`id`),
  UNIQUE KEY `number_UNIQUE` (`number`),
  UNIQUE KEY `ufsrvuid` (`ufsrvuid`),
  KEY `authenticated_device_cookie_index` (`accounts_authenticated_device_cookie`),
  KEY `accounts_authenticated_device_cookie` (`accounts_authenticated_device_cookie`),
  KEY `accounts_nickname` (`accounts_nickname`),
  KEY `accounts_authenticated_device_gcm_id` (`accounts_authenticated_device_gcm_id`),
  CHECK (data IS NULL OR JSON_VALID(data)),
  CHECK (data_user IS NULL OR JSON_VALID(data_user))
) ENGINE=InnoDB AUTO_INCREMENT=299 DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `attachments`
--

DROP TABLE IF EXISTS `attachments`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `attachments` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `userid` INT(20) UNSIGNED NOT NULL,
  `device_id` tinyint(4) NOT NULL DEFAULT '1',
  `key` text,
  `digest` text,
  `blurhash` text,
  `caption` text,
  `blob_id` varchar(255) NOT NULL,
  `fid` bigint(20) NOT NULL DEFAULT '0',
  `mimetype` tinytext,
  `key_size` INT(20) UNSIGNED DEFAULT '0',
  `digest_size` bigint(20) DEFAULT '0',
  `size` INT(20) UNSIGNED DEFAULT NULL,
  `id_events` bigint(20) DEFAULT NULL,
  `thumbnail` blob,
  `timestamp` datetime DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `blob_id_UNIQUE` (`blob_id`),
  KEY `attachments_fid_index` (`fid`),
  KEY `attachments_userid_index` (`userid`)
) ENGINE=InnoDB AUTO_INCREMENT=57 DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `fences`
--

DROP TABLE IF EXISTS `fences`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `fences` (
  `fid` bigint(20) NOT NULL,
  `data` json DEFAULT NULL,
  PRIMARY KEY (`fid`),
  UNIQUE KEY `fid_UNIQUE` (`fid`),
  CHECK (data IS NULL OR JSON_VALID(data))
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `keys`
--

DROP TABLE IF EXISTS `keys`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `keys` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `number` varchar(255) NOT NULL,
  `device_id` bigint(20) NOT NULL DEFAULT '1',
  `key_id` bigint(20) NOT NULL,
  `public_key` text NOT NULL,
  `last_resort` smallint(6) NOT NULL DEFAULT '0',
  PRIMARY KEY (`id`),
  UNIQUE KEY `key_id_UNIQUE` (`key_id`),
  UNIQUE KEY `id_UNIQUE` (`id`),
  KEY `keys_number_index` (`number`)
) ENGINE=InnoDB AUTO_INCREMENT=14687 DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `messages`
--

DROP TABLE IF EXISTS `messages`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `messages` (
  `id` INT(11) UNSIGNED NOT NULL AUTO_INCREMENT,
  `id_events` INT(11) UNSIGNED NOT NULL,
  `fid` bigint(20) DEFAULT '0',
  `type` tinyint(4) NOT NULL,
  `status` tinyint(4),
  `rawmsg` text NOT NULL,
  `timestamp` bigint(20) NOT NULL,
  `originator` bigint(20) NOT NULL,
  `originator_device` int(11) NOT NULL DEFAULT '1',
  PRIMARY KEY (`id`),
  FOREIGN KEY fk_id_events(id_events)
      REFERENCES events(id)
      ON DELETE CASCADE,
  KEY `fid_index` (`fid`),
  KEY `eid_index` (`id_events`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `messages`
--

DROP TABLE IF EXISTS `guardians`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `guardians` (
    `id` INT(20) UNSIGNED NOT NULL AUTO_INCREMENT,
    `guardian` INT(20) UNSIGNED NOT NULL,
    `originator` INT(20) UNSIGNED NOT NULL,
    `status` tinyint(4),
    `timestamp` BIGINT(20) UNSIGNED NOT NULL,
    `gid` BIGINT(20) UNSIGNED NOT NULL DEFAULT '0',
    `data` json DEFAULT NULL,
    PRIMARY KEY (`id`),
    UNIQUE KEY `originator_guardian_status_unique_index`(`originator`, `guardian`, `status`),
    CHECK (data IS NULL OR JSON_VALID(data))
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `events`
--

DROP TABLE IF EXISTS `events`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `events` (
    `id` BIGINT(20) UNSIGNED NOT NULL AUTO_INCREMENT,
    `eid` BIGINT(20) UNSIGNED NOT NULL DEFAULT '0',
    `ctxid` BIGINT(20) UNSIGNED,
    `cmd_type` tinyint(4) NOT NULL DEFAULT '0',
    `event_type` tinyint(4) NOT NULL DEFAULT '0',
    `rawmsg` text,
    `timestamp` bigint(20) NOT NULL,
    `originator` bigint(20) NOT NULL,
    PRIMARY KEY (`id`),
    UNIQUE KEY `eid_ctxid_originator_unique_index`(`eid`, `ctxid`, `originator`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

DROP TABLE IF EXISTS `flagged_events`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `flagged_events` (
                          `id` INT(11) UNSIGNED NOT NULL,
                          `timestamp` bigint(20) NOT NULL,
                          `originator` bigint(20) NOT NULL,
                          FOREIGN KEY fk_id(id)
                              REFERENCES events(id)
                              ON DELETE CASCADE,
                          UNIQUE KEY `id_originator_unique_index`(`id`, `originator`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `pending_accounts`
--

DROP TABLE IF EXISTS `pending_accounts`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `pending_accounts` (
  `id` INT(20) UNSIGNED NOT NULL AUTO_INCREMENT,
  `number` varchar(255) NOT NULL,
  `password` varchar(255) DEFAULT NULL,
  `cookie` varchar(255) DEFAULT NULL,
  `verification_code` varchar(255) NOT NULL,
  `when` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `returning` tinyint(1) NOT NULL DEFAULT '0',
  PRIMARY KEY (`id`),
  UNIQUE KEY `id_UNIQUE` (`id`),
  UNIQUE KEY `number_UNIQUE` (`number`)
) ENGINE=InnoDB AUTO_INCREMENT=240 DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `pending_devices`
--

DROP TABLE IF EXISTS `pending_devices`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `pending_devices` (
  `id` INT(20) UNSIGNED NOT NULL AUTO_INCREMENT,
  `number` varchar(255) NOT NULL,
  `password` varchar(255) DEFAULT NULL,
  `cookie` varchar(255) DEFAULT NULL,
  `verification_code` varchar(255) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `number_UNIQUE` (`number`),
  UNIQUE KEY `id_UNIQUE` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `ufsrv_geogroups`
--

DROP TABLE IF EXISTS `ufsrv_geogroups`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `ufsrv_geogroups` (
  `code` int(4) NOT NULL COMMENT 'Data center code',
  `name` varchar(255) DEFAULT NULL,
  `continent_code` char(2) NOT NULL,
  PRIMARY KEY (`code`),
  UNIQUE KEY `idx_code` (`code`) USING BTREE,
  KEY `idx_continent_code` (`continent_code`) USING BTREE,
  CONSTRAINT `ufsrv_geogroups_fk_1` FOREIGN KEY (`continent_code`) REFERENCES `continents` (`code`) ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8 ROW_FORMAT=COMPACT;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;

--
-- Table structure for table `continents`
--

DROP TABLE IF EXISTS `continents`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `continents` (
  `code` char(2) NOT NULL COMMENT 'Continent code',
  `name` varchar(255) DEFAULT NULL,
  PRIMARY KEY (`code`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8 ROW_FORMAT=COMPACT;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `countries`
--

DROP TABLE IF EXISTS `countries`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `countries` (
  `country_id` int(11) NOT NULL AUTO_INCREMENT,
  `code` char(2) NOT NULL COMMENT 'Two-letter country code (ISO 3166-1 alpha-2)',
  `name` varchar(64) NOT NULL COMMENT 'English country name',
  `full_name` varchar(128) NOT NULL COMMENT 'Full English country name',
  `iso3` char(3) NOT NULL COMMENT 'Three-letter country code (ISO 3166-1 alpha-3)',
  `number` smallint(3) unsigned zerofill NOT NULL COMMENT 'Three-digit country number (ISO 3166-1 numeric)',
  `continent_code` char(2) NOT NULL,
  `display_order` int(3) NOT NULL DEFAULT '900',
  `geogroup_code` int(4) NOT NULL DEFAULT '3',
  PRIMARY KEY (`country_id`),
  UNIQUE KEY `idx_code` (`code`) USING BTREE,
  KEY `idx_continent_code` (`continent_code`) USING BTREE,
  CONSTRAINT `countries_ibfk_1` FOREIGN KEY (`continent_code`) REFERENCES `continents` (`code`) ON UPDATE CASCADE
) ENGINE=InnoDB AUTO_INCREMENT=247 DEFAULT CHARSET=utf8 ROW_FORMAT=COMPACT;
/*!40101 SET character_set_client = @saved_cs_client */;

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;

-- Dump completed on 2017-08-20 21:34:22
