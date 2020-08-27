-- Table: public.k_pods

-- DROP TABLE public.k_pods;

CREATE TABLE public.k_pods
(
    podname character varying COLLATE pg_catalog."default" NOT NULL,
    report_uid character varying COLLATE pg_catalog."default" NOT NULL,
    namespace_uid character varying COLLATE pg_catalog."default" NOT NULL,
    uid character varying COLLATE pg_catalog."default" NOT NULL,
    creation_timestamp date NOT NULL,
    kubernetes_pod_uid character varying COLLATE pg_catalog."default",
    CONSTRAINT k_pods_pkey PRIMARY KEY (report_uid, namespace_uid, uid),
    CONSTRAINT k_pods_uid_key UNIQUE (uid),
    CONSTRAINT k_pods_namespace_uid_fkey FOREIGN KEY (namespace_uid)
        REFERENCES public.k_namespaces (uid) MATCH SIMPLE
        ON UPDATE NO ACTION
        ON DELETE NO ACTION
        NOT VALID,
    CONSTRAINT k_pods_report_uid_fkey FOREIGN KEY (report_uid)
        REFERENCES public.k_reports (uid) MATCH SIMPLE
        ON UPDATE NO ACTION
        ON DELETE CASCADE
        NOT VALID
)
WITH (
    OIDS = FALSE
)
TABLESPACE pg_default;

ALTER TABLE public.k_pods
    OWNER to postgres;
-- Index: k_pods_namespace_uid_fkey

-- DROP INDEX public.k_pods_namespace_uid_fkey;

CREATE INDEX k_pods_namespace_uid_fkey
    ON public.k_pods USING btree
    (namespace_uid COLLATE pg_catalog."default" ASC NULLS LAST)
    TABLESPACE pg_default;
-- Index: k_pods_report_uid_fkey

-- DROP INDEX public.k_pods_report_uid_fkey;

CREATE INDEX k_pods_report_uid_fkey
    ON public.k_pods USING btree
    (report_uid COLLATE pg_catalog."default" ASC NULLS LAST)
    TABLESPACE pg_default;