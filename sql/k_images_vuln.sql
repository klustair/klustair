-- Table: public.k_images_vuln

-- DROP TABLE public.k_images_vuln;

CREATE TABLE public.k_images_vuln
(
    uid character varying COLLATE pg_catalog."default" NOT NULL,
    image_uid character varying COLLATE pg_catalog."default",
    report_uid character varying COLLATE pg_catalog."default",
    feed character varying COLLATE pg_catalog."default",
    feed_group character varying COLLATE pg_catalog."default",
    fix character varying COLLATE pg_catalog."default",
    nvd_data_id character varying COLLATE pg_catalog."default",
    nvd_data_base_score double precision,
    nvd_data_exploitability_score double precision,
    nvd_data_impact_score double precision,
    package_fullname character varying COLLATE pg_catalog."default",
    package_cpe character varying COLLATE pg_catalog."default",
    package_cpe23 character varying COLLATE pg_catalog."default",
    package_name character varying COLLATE pg_catalog."default",
    package_path character varying COLLATE pg_catalog."default",
    package_type character varying COLLATE pg_catalog."default",
    package_version character varying COLLATE pg_catalog."default",
    severity vulnerability_severities,
    url character varying COLLATE pg_catalog."default",
    vuln character varying COLLATE pg_catalog."default",
    CONSTRAINT k_images_vuln_pkey PRIMARY KEY (uid),
    CONSTRAINT k_images_vuln_report_uid_fkey FOREIGN KEY (report_uid)
        REFERENCES public.k_reports (uid) MATCH SIMPLE
        ON UPDATE NO ACTION
        ON DELETE CASCADE
        NOT VALID
)
WITH (
    OIDS = FALSE
)
TABLESPACE pg_default;

ALTER TABLE public.k_images_vuln
    OWNER to postgres;
-- Index: k_images_vuln_report_uid_fkey

-- DROP INDEX public.k_images_vuln_report_uid_fkey;

CREATE INDEX k_images_vuln_report_uid_fkey
    ON public.k_images_vuln USING btree
    (report_uid COLLATE pg_catalog."default" ASC NULLS LAST)
    TABLESPACE pg_default;