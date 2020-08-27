-- Table: public.k_images

-- DROP TABLE public.k_images;

CREATE TABLE public.k_images
(
    image_size bigint,
    layer_count bigint,
    uid character varying COLLATE pg_catalog."default",
    image_digest character varying COLLATE pg_catalog."default",
    fulltag character varying COLLATE pg_catalog."default",
    arch character varying(15) COLLATE pg_catalog."default",
    anchore_imageid character varying COLLATE pg_catalog."default",
    distro character varying COLLATE pg_catalog."default",
    distro_version character varying COLLATE pg_catalog."default",
    created_at timestamp without time zone,
    analyzed_at timestamp without time zone,
    registry character varying COLLATE pg_catalog."default",
    repo character varying COLLATE pg_catalog."default",
    report_uid character varying COLLATE pg_catalog."default",
    dockerfile text COLLATE pg_catalog."default",
    CONSTRAINT k_images_report_uid_fkey FOREIGN KEY (report_uid)
        REFERENCES public.k_reports (uid) MATCH SIMPLE
        ON UPDATE NO ACTION
        ON DELETE CASCADE
        NOT VALID
)
WITH (
    OIDS = FALSE
)
TABLESPACE pg_default;

ALTER TABLE public.k_images
    OWNER to postgres;
-- Index: k_images_report_uid_fkey

-- DROP INDEX public.k_images_report_uid_fkey;

CREATE INDEX k_images_report_uid_fkey
    ON public.k_images USING btree
    (report_uid COLLATE pg_catalog."default" ASC NULLS LAST)
    TABLESPACE pg_default;