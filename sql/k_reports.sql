-- Table: public.k_reports

-- DROP TABLE public.k_reports;

CREATE TABLE public.k_reports
(
    uid character varying COLLATE pg_catalog."default" NOT NULL,
    checktime timestamp with time zone NOT NULL,
    CONSTRAINT k_reports_pkey PRIMARY KEY (uid),
    CONSTRAINT k_reports_uid_key UNIQUE (uid)
)
WITH (
    OIDS = FALSE
)
TABLESPACE pg_default;

ALTER TABLE public.k_reports
    OWNER to postgres;