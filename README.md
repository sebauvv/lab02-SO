# Explicación de lo realizado

Lo siguiente contiene lo que se ha logrado avanzar y abordando algunos puntos específicos que no se pueden contestar de la plantilla adjunta al laboratorio.

## Ejercicio 01

En lo que es acceso a la memoria de usuario, se realizó:

1. **Validación de Punteros**: Se implementó una función para validar que los punteros proporcionados por los programas de usuario apunten a direcciones válidas en el espacio de usuario. Esto incluye verificar que las direcciones no sean nulas, que no apunten a direcciones del kernel y que estén mapeadas en el espacio de direcciones del proceso.

2. **Lectura de Memoria de Usuario**: Tambien creamos una función para leer datos desde la memoria de usuario. Esta  toma un puntero de usuario y una longitud, y copia los datos desde el espacio de usuario al espacio del kernel. Durante esta operación, se verifica que cada dirección de memoria sea válida.

3. **Escritura en Memoria de Usuario**: Similar a la lectura, se implementó una función para escribir datos en la memoria de usuario. Esta toma un puntero de usuario, una longitud y los datos a escribir, y copia los datos desde el espacio del kernel al espacio de usuario, validando las direcciones de memoria en el proceso.

### Implementación de la syscall `write`

Para implementar la syscall `write`, se siguieron estos pasos:

1. **Definición de este Prototipo**: Se definió a `write` en el archivo de cabecera correspondiente (`syscall.h`), asegurándose de que coincida con la firma esperada por los programas de usuario.

2. **Registro de la Syscall**: En la función `syscall_init`, se registró la syscall `write` en la tabla de manejadores de syscalls (`syscall_executors`). Esto es porque permite que el manejador de interrupciones de syscalls (`syscall_handler`) pueda invocar la función correspondiente cuando se realiza una llamada a `write`.

3. **Implementación del Manejador de `write`**: Se implementó `write_executor` en `syscall.c`. Esta función realiza las siguientes acciones:
   - Extrae los argumentos de la syscall desde el marco de interrupción (`intr_frame`), que incluye el descriptor de archivo, el puntero al buffer de datos y el tamaño de los datos a escribir.
   - Valida los argumentos, asegurándose de que el descriptor de archivo sea válido y que el buffer de datos apunte a una dirección de memoria de usuario válida.
   - Utiliza la función de acceso a memoria de usuario para leer los datos desde el buffer de usuario.
   - Llama a la función correspondiente del sistema de archivos para escribir los datos en el archivo especificado por el descriptor de archivo.
   - Devuelve el número de bytes escritos o un código de error si la operación falla.

### Ejemplo de Código

#### Validación de Punteros
```c
static bool is_user_vaddr(const void *vaddr) {
  return vaddr < PHYS_BASE;
}

static void validate_user_pointer(const void *vaddr) {
  if (!is_user_vaddr(vaddr) || pagedir_get_page(thread_current()->pagedir, vaddr) == NULL) {
    thread_exit();
  }
}
```
#### Lectura de Memoria de Usuario

```c
static int copy_from_user(void *kernel_dst, const void *user_src, size_t size) {
  validate_user_pointer(user_src);
  memcpy(kernel_dst, user_src, size);
  return size;
}

```
#### Implementación de write_executor

```c
static int write_executor(void *args) {
  struct intr_frame *f = args;
  int fd = *(int *)(f->esp + 4);
  const void *buffer = *(void **)(f->esp + 8);
  unsigned size = *(unsigned *)(f->esp + 12);

  validate_user_pointer(buffer);

  if (fd == STDOUT_FILENO) {
    putbuf(buffer, size);
    return size;
  } else {
    struct file *file = thread_current()->fd_table[fd];
    if (file == NULL) {
      return -1;
    }
    return file_write(file, buffer, size);
  }
}
```

## Ejercicio 02: Implementación de Paginación Lazy para Segmentos de Ejecutables


Para esto se realizaron varias modificaciones en los archivos dentro de las carpetas `userprog` y `vm`. 

### 1. Cambio corto de `load_segment` en `src/userprog/process.c`

La función `load_segment` en `src/userprog/process.c` fue modificada. En lugar de cargar todas las páginas del segmento inmediatamente, load_segment ahora registra la información de cada página en una estructura `map_file` y la almacena en una tabla de mapeo de archivos. Esto permite que las páginas se carguen de manera lazy cuando se acceden por primera vez.

```c
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
              uint32_t read_bytes, uint32_t zero_bytes, bool writable) 
{
  ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT (pg_ofs (upage) == 0);
  ASSERT (ofs % PGSIZE == 0);

  struct process_meta *meta = thread_current ()->meta;
  void *rt = meta->map_file_rt;
  while (zero_bytes > 0 || read_bytes > 0)
    {
      size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
      size_t page_zero_bytes = PGSIZE - page_read_bytes;

      struct map_file *mf = malloc (sizeof (struct map_file));
      if (mf == NULL)
        return false;

      mf->fobj = file_reopen (file);
      mf->writable = writable;
      mf->offset = ofs;
      mf->read_bytes = page_read_bytes;

      if (!map_file (rt, mf, upage)) {
        return false;
      }

      ofs += page_read_bytes;
      read_bytes -= page_read_bytes;
      zero_bytes -= page_zero_bytes;
      upage += PGSIZE;
    }
  return true;
}

```

### 2. Manejo de Fallos de Página en src/userprog/exception.c

Se modificó la función `page_fault` en `src/userprog/exception.c`. Cuando ocurre un fallo de página, se verifica si la dirección de la página es válida y si la página no está presente en la memoria. Si la página no está presente, se intenta cargar la página desde el archivo o el dispositivo de swap utilizando la función `vm_fetch_page`.

```c
static void
page_fault (struct intr_frame *f) 
{
  bool not_present;
  bool write;
  bool user;
  void *fault_addr;

  asm ("movl %%cr2, %0" "=r" (fault_addr));
  intr_enable ();
  page_fault_cnt++;

  not_present = (f->error_code & PF_P) == 0;
  write = (f->error_code & PF_W) != 0;
  user = (f->error_code & PF_U) != 0;

  if (user) {
    struct thread *cur = thread_current ();
    if (!is_user_vaddr (fault_addr))
      goto kill_user;
    if (pagedir_get_page (cur->pagedir, fault_addr) != NULL)
      goto kill_user;

    if (vm_fetch_page (pg_round_down (fault_addr))) {
      return;
    }

    if (not_present && validate_stack (f->esp) && fault_addr >= f->esp - 32) {
      void *page = vm_alloc_page (0, pg_round_down (fault_addr));
      if (page == NULL)
        goto kill_user;

      pagedir_set_page (cur->pagedir, pg_round_down (fault_addr), page, true);
      return;
    }

  kill_user:
    f->eip = (void (*) (void)) f->eax;
    f->eax = -1;
    process_terminate (-1);
    return;
  }

  printf ("Page fault at %p: %s error %s page in %s context.\n",
          fault_addr,
          not_present ? "not present" : "rights violation",
          write ? "writing" : "reading",
          user ? "user" : "kernel");
  kill (f);
}
```

### 3. Funciones de Manejo de Páginas en src/vm/vm_util.c

Se implementaron funciones en `src/vm/vm_util.c`. Primero, verifica si la página está en el dispositivo de swap y la carga si es necesario. Si la página no está en el dispositivo de swap, intenta cargarla desde el archivo utilizando la información almacenada en la tabla de mapeo de archivos.

```c
void *
vm_fetch_page (void *upage)
{
  if (upage == NULL || !is_user_vaddr (upage)) {
    goto vm_not_found;
  }

  struct thread *cur = thread_current ();
  struct process_meta *meta = cur->meta;
  struct frame_table *ftb = &meta->frametb;
  struct swap_table_root *swaptb = meta->swaptb;

  unsigned int *ste = swaptb_lookup (swaptb, upage);
  if (ste != NULL && (*ste & STE_V) != 0)
    {
      unsigned sec = ste_get_blockno (*ste);
      void *page = vm_alloc_page (0, upage);
      ASSERT (page != NULL); 
      swaptb_read_page (sec, page);
      swaptb_free_sec (sec);
      pagedir_set_page (cur->pagedir, upage, page, 1);
      *ste = 0x0;
      return page;
    }

  struct map_file *mf = map_file_lookup (meta->map_file_rt, upage);
  if (mf == NULL)
    goto vm_not_found;
  void *page = vm_alloc_page (0, upage);
  if (map_file_init_page (mf, page))
    {
      pagedir_set_page (cur->pagedir, upage, page, mf->writable);
      return page;
    }
  else 
    {
      for (int i = 0; i < ftb->free_ptr; ++i) {
        if (ftb->pages[i] == page)
          {
            ftb->upages[i] = NULL;
          }
      }
    }

vm_not_found:
  return NULL;
}
```

### 4. Funciones de Mapeo de Archivos en src/vm/map_file.c

Esta función asigna una nueva entrada en la tabla de mapeo de archivos para cada página del archivo que se va a cargar de manera lazy.

```c
bool 
map_file (void *rt, struct map_file *mf, void *uaddr)
{
  if (rt == NULL) {
    PANIC ("map file table not initialized");
  }
  unsigned int idx = mf_root_index (uaddr);
  void **dirptr = rt;
  struct map_file **entries = dirptr[idx];
  if (entries == NULL) {
    void *pg = palloc_get_page (0);
    if (pg == NULL) {
      free (mf);
      return false;
    }
    memset (pg, 0, PGSIZE);
    dirptr[idx] = pg;
    entries = dirptr[idx];
  }
  ASSERT (entries != NULL);
  idx = mf_dir_index (uaddr);
  if (entries[idx] != NULL) {
    free (mf);
    return false;
  }
  entries[idx] = mf;
  return true;
}
```
## Stack Growth


### Instalación de stack

La función `sc_install_stack` se encarga de instalar nuevas páginas en la pila cuando sea necesario. Verifica que los argumentos sean válidos y que la dirección de la pila esté dentro de los límites permitidos. Luego, intenta asignar y configurar nuevas páginas en la pila utilizando `palloc_get_page` o `vm_alloc_page`.

```c
static void
sc_install_stack (uint32_t *pagetable, void *esp, void *start, void *end)
{
  ASSERT (start < end);
  if (esp < 0x8048000 || end > PHYS_BASE || start < esp) {
    return;
  }

  void *page = pg_round_down (start);
  for (; page < pg_round_up (end); page += PGSIZE) 
    {
      void *kaddr = pagedir_get_page (pagetable, page);
      if (kaddr != NULL) {
        continue;
      }

#ifndef VM
      kaddr = palloc_get_page (PAL_USER);
#else
      kaddr = vm_alloc_page (0, page);
#endif
      if (kaddr == NULL) {
        return;
      }
      pagedir_set_page (pagetable, page, kaddr, true);
    }
}
```

### Validación de la Pila

```c
static bool
validate_stack (void *esp) 
{
  return (esp <= PHYS_BASE) && (esp >= STACK_LOW);
}
```

###  Manejo de Fallos de Página en exception.c

La función `page_fault` se encarga de manejar los fallos de página. Cuando ocurre un fallo de página, se verifica si la dirección de la página es válida y si la página no está presente en la memoria. Si la página no está presente y la dirección de la pila es válida, se intenta asignar una nueva página para la pila utilizando `palloc_get_page` o `vm_alloc_page`. Esto permite que la pila crezca dinámicamente conforme sea necesario.


```c
static void
page_fault (struct intr_frame *f) 
{
  bool not_present;  
  bool write;        
  bool user;         
  void *fault_addr;  

  asm ("movl %%cr2, %0" : "=r" (fault_addr));
  intr_enable ();
  page_fault_cnt++;

  not_present = (f->error_code & PF_P) == 0;
  write = (f->error_code & PF_W) != 0;
  user = (f->error_code & PF_U) != 0;

  if (user) {
    struct thread *cur = thread_current ();
    if (!is_user_vaddr (fault_addr)) 
      goto kill_user;
    if (pagedir_get_page (cur->pagedir, fault_addr) != NULL)
      goto kill_user;
#ifdef VM
    if (vm_fetch_page (pg_round_down (fault_addr))) {
      return;
    }
#endif

#ifdef USERPROG
    if (not_present && validate_stack (f->esp) && fault_addr >= f->esp - 32) {
#ifndef VM
      void *page = palloc_get_page (PAL_USER);
#else
      void *page = vm_alloc_page (0, pg_round_down (fault_addr));
#endif
      if (page == NULL) 
        goto kill_user;
      
      struct thread *cur = thread_current ();
      pagedir_set_page (cur->pagedir, pg_round_down (fault_addr),
                        page, true);

      return;
    }

#endif
  kill_user:
   f->eip = (void (*) (void)) f->eax;
   f->eax = -1;
   process_terminate (-1);
   return;
  }

  printf ("Page fault at %p: %s error %s page in %s context.\n",
          fault_addr,
          not_present ? "not present" : "rights violation",
          write ? "writing" : "reading",
          user ? "user" : "kernel");
  kill (f);
}
```