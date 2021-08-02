package tacos;

import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.security.crypto.password.PasswordEncoder;

import tacos.Ingredient.Type;
import tacos.data.IngredientRepository;
import tacos.data.UserRepository;

@Profile("!prod")
@Configuration
public class DevelopmentConfig {

  @Bean
  public CommandLineRunner dataLoader(IngredientRepository repo,
        UserRepository userRepo, PasswordEncoder encoder) { // Repozytorium użytkownika do przetestowania wraz z profilem użytkownika wbudowanego
    return new CommandLineRunner() {
      @Override
      public void run(String... args) throws Exception {
        repo.save(new Ingredient("FLTO", "pszenna", Type.WRAP));
        repo.save(new Ingredient("COTO", "kukurydziana", Type.WRAP));
        repo.save(new Ingredient("GRBF", "mielona wołowina", Type.PROTEIN));
        repo.save(new Ingredient("CARN", "kawałki mięsa", Type.PROTEIN));
        repo.save(new Ingredient("TMTO", "pomidory pokrojone w kostkę", Type.VEGGIES));
        repo.save(new Ingredient("LETC", "sałata", Type.VEGGIES));
        repo.save(new Ingredient("CHED", "cheddar", Type.CHEESE));
        repo.save(new Ingredient("JACK", "Monterrey Jack", Type.CHEESE));
        repo.save(new Ingredient("SLSA", "pikantny sos pomidorowy", Type.SAUCE));
        repo.save(new Ingredient("SRCR", "śmietana", Type.SAUCE));
        
        
        userRepo.save(new User("habuma", encoder.encode("password"), 
            "Jan Kowalski", "ul. Dobra 123", "Gliwice", "śląskie", 
            "76227", "123-123-1234"));
      }
    };
  }
  
}
