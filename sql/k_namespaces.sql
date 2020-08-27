-- Table: public.k_namespaces

-- DROP TABLE public.k_namespaces;

CREATE TABLE public.k_namespaces
(
    name character varying COLLATE pg_catalog."default" NOT NULL,
    uid character varying COLLATE pg_catalog."default" NOT NULL,
    report_uid character varying COLLATE pg_catalog."default" NOT NULL,
    creation_timestamp timestamp with time zone NOT NULL,
    kubernetes_namespace_uid character varying COLLATE pg_catalog."default",
    CONSTRAINT k_namespaces_pkey PRIMARY KEY (report_uid, uid),
    CONSTRAINT k_namespaces_uid_key UNIQUE (uid),
    CONSTRAINT k_namespaces_report_uid_fkey FOREIGN KEY (report_uid)
        REFERENCES public.k_reports (uid) MATCH SIMPLE
        ON UPDATE NO ACTION
        ON DELETE CASCADE
        NOT VALID
)
WITH (
    OIDS = FALSE
)
TABLESPACE pg_default;

ALTER TABLE public.k_namespaces
    OWNER to postgres;
-- Index: k_namespaces_report_uid_fkey

-- DROP INDEX public.k_namespaces_report_uid_fkey;

CREATE INDEX k_namespaces_report_uid_fkey
    ON public.k_namespaces USING btree
    (report_uid COLLATE pg_catalog."default" ASC NULLS LAST)
    TABLESPACE pg_default;