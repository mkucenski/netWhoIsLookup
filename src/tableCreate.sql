CREATE TABLE `tbl_Case` (
  `CaseID` varchar(100) NOT NULL DEFAULT '',
  `IP` varchar(100) NOT NULL DEFAULT '',
  PRIMARY KEY (`IP`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1; 

CREATE TABLE `tbl_IP` (
  `IP` varchar(100) NOT NULL DEFAULT '',
  `Netmask` varchar(100) NOT NULL DEFAULT '',
  PRIMARY KEY (`IP`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1; 

CREATE TABLE `tbl_IPFail` (
  `IP` varchar(100) NOT NULL DEFAULT '',
  `Raw` mediumtext,
  `XML` mediumtext,
  `Timestamp` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`IP`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1; 

CREATE TABLE `tbl_Netmask` (
  `Netmask` varchar(100) NOT NULL DEFAULT '',
  `ID` varchar(100) DEFAULT '',
  `Name` varchar(100) NOT NULL DEFAULT '',
  `Description` varchar(1000) DEFAULT '',
  `Address` varchar(1000) DEFAULT '',
  `City` varchar(100) DEFAULT '',
  `State` varchar(100) DEFAULT '',
  `Zip` varchar(100) DEFAULT '',
  `Country` varchar(100) NOT NULL DEFAULT '',
  `WhoisServer` varchar(100) NOT NULL DEFAULT '',
  `Timestamp` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`Netmask`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1; 

CREATE TABLE `tbl_NetmaskRaw` (
  `Netmask` varchar(100) NOT NULL DEFAULT '',
  `Raw` mediumtext NOT NULL,
  `XML` mediumtext,
  PRIMARY KEY (`Netmask`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1; 

