"""
Basic Usage Example for DCATS

This example shows how to use the DCATS system for basic AI interactions
with built-in security and oversight.
"""

import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from src.dcats import DualLayerAI, DCATSInput

def basic_usage_example():
    """Basic usage example of the DCATS system"""
    
    print("DCATS Basic Usage Example")
    print("=" * 25)
    
    # Initialize the DCATS system
    ai_system = DualLayerAI(initial_trust=0.5)
    
    # Simple query
    user_input = DCATSInput(
        query="What is artificial intelligence?",
        context={"session_type": "educational"},
        user_metadata={"authenticated": True}
    )
    
    # Process the query
    result = ai_system.process(user_input)
    
    # Display results
    print(f"Query: {user_input.query}")
    print(f"Response: {result.response}")
    print(f"Trust Score: {result.trust_score:.3f}")
    print(f"Confidence: {result.confidence:.3f}")
    print()
    
    # Check system status
    status = ai_system.get_system_status()
    print("System Status:")
    print(f"  Trust Level: {status['trust_metrics']['trust_level']}")
    print(f"  Queries Processed: {status['session_stats']['total_queries']}")
    print(f"  System Health: {status['system_health']}")

def interactive_demo():
    """Interactive demonstration"""
    
    print("\nInteractive DCATS Demo")
    print("=" * 21)
    print("Type 'quit' to exit")
    print()
    
    ai_system = DualLayerAI(initial_trust=0.6)
    
    while True:
        try:
            user_query = input("Enter your query: ").strip()
            
            if user_query.lower() in ['quit', 'exit', 'q']:
                break
            
            if not user_query:
                continue
            
            # Process the query
            dcats_input = DCATSInput(
                query=user_query,
                context={"session": "interactive"},
                user_metadata={"authenticated": True}
            )
            
            result = ai_system.process(dcats_input)
            
            print(f"\nResponse: {result.response}")
            print(f"Trust: {result.trust_score:.3f} | Confidence: {result.confidence:.3f}")
            
            # Show security actions if any
            if any(result.security_actions.values()):
                print(f"Security Actions: {result.security_actions}")
            
            print("-" * 40)
            
        except KeyboardInterrupt:
            break
        except Exception as e:
            print(f"Error: {e}")
    
    print("\nFinal System Status:")
    status = ai_system.get_system_status()
    print(f"Total Queries: {status['session_stats']['total_queries']}")
    print(f"Successful Interactions: {status['session_stats']['successful_interactions']}")
    print(f"Final Trust Score: {status['trust_metrics']['current_score']:.3f}")

if __name__ == "__main__":
    basic_usage_example()
    interactive_demo()